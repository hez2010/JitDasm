/*
Copyright (C) 2019 de4dot@gmail.com
Copyright (C) 2021 hez2010@outlook.com

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using Iced.Intel;
using Microsoft.Diagnostics.Runtime;

namespace JitDasm {
	static class Program {
		const string DASM_EXT = ".dasm";
		const ulong MIN_ADDR = 0x10000;

		static int Main(string[] args) {
			try {
				switch (System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture) {
				case System.Runtime.InteropServices.Architecture.X64:
				case System.Runtime.InteropServices.Architecture.X86:
					break;
				default:
					throw new ApplicationException($"Unsupported CPU arch: {System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}");
				}

				var jitDasmOptions = CommandLineParser.Parse(args);
				if (!string.IsNullOrEmpty(jitDasmOptions.LoadModule)) {
#if DEBUG
					Console.Error.WriteLine($"Trying to jit methods in module '{jitDasmOptions.LoadModule}' but JitDasm is a debug build, not a release build!");
#endif
					MethodJitter.JitMethods(jitDasmOptions.LoadModule, jitDasmOptions.TypeFilter, jitDasmOptions.MethodFilter, jitDasmOptions.RunClassConstructors, jitDasmOptions.AssemblySearchPaths);
				}
				var (bitness, methods, knownSymbols) = GetMethodsToDisassemble(jitDasmOptions.Pid, jitDasmOptions.ModuleName, jitDasmOptions.TypeFilter, jitDasmOptions.MethodFilter, jitDasmOptions.HeapSearch);
				var jobs = GetJobs(methods, jitDasmOptions.OutputDir, jitDasmOptions.FileOutputKind, jitDasmOptions.FilenameFormat, out var baseDir);
				if (!string.IsNullOrEmpty(baseDir))
					Directory.CreateDirectory(baseDir);
				var sourceDocumentProvider = new SourceDocumentProvider();
				using (var mdProvider = new MetadataProvider()) {
					var sourceCodeProvider = new SourceCodeProvider(mdProvider, sourceDocumentProvider);
					using var context = new DisasmJobContext(bitness, knownSymbols, sourceCodeProvider, jitDasmOptions.DisassemblerOutputKind, jitDasmOptions.Diffable, jitDasmOptions.ShowAddresses, jitDasmOptions.ShowHexBytes, jitDasmOptions.ShowSourceCode);
					foreach (var job in jobs)
						Disassemble(context, job);
				}
				return 0;
			}
			catch (ShowCommandLineHelpException) {
				CommandLineParser.ShowHelp();
				return 1;
			}
			catch (CommandLineParserException ex) {
				Console.WriteLine(ex.Message);
				return 1;
			}
			catch (ApplicationException ex) {
				Console.WriteLine(ex.Message);
				return 1;
			}
			catch (ClrDiagnosticsException ex) {
				Console.WriteLine(ex.Message);
				Console.WriteLine("Make sure this process has the same bitness as the target process");
				return 1;
			}
			catch (Exception ex) {
				Console.WriteLine(ex.ToString());
				return 1;
			}
		}

		sealed class DisasmJob {
			public readonly Func<(TextWriter writer, bool close)> GetTextWriter;
			public readonly DisasmInfo[] Methods;
			public DisasmJob(Func<(TextWriter writer, bool close)> getTextWriter, DisasmInfo[] methods) {
				GetTextWriter = getTextWriter;
				Methods = methods;
			}
		}

		sealed class DisasmJobContext : IDisposable {
			readonly SourceCodeProvider sourceCodeProvider;
			public readonly Disassembler Disassembler;
			public readonly Formatter Formatter;
			public DisasmJobContext(int bitness, KnownSymbols knownSymbols, SourceCodeProvider sourceCodeProvider, DisassemblerOutputKind disassemblerOutputKind, bool diffable, bool showAddresses, bool showHexBytes, bool showSourceCode) {
				var disassemblerOptions = DisassemblerOptions.None;
				if (diffable)
					disassemblerOptions |= DisassemblerOptions.Diffable;
				if (showAddresses)
					disassemblerOptions |= DisassemblerOptions.ShowAddresses;
				if (showHexBytes)
					disassemblerOptions |= DisassemblerOptions.ShowHexBytes;
				if (showSourceCode)
					disassemblerOptions |= DisassemblerOptions.ShowSourceCode;
				string commentPrefix = disassemblerOutputKind switch {
					DisassemblerOutputKind.Masm or DisassemblerOutputKind.Nasm or DisassemblerOutputKind.Intel => "; ",
					DisassemblerOutputKind.Gas => "// ",
					_ => throw new ArgumentOutOfRangeException(nameof(disassemblerOutputKind)),
				};
				this.sourceCodeProvider = sourceCodeProvider;
				Disassembler = new Disassembler(bitness, commentPrefix, sourceCodeProvider, knownSymbols, disassemblerOptions);
				Formatter = CreateFormatter(Disassembler.SymbolResolver, diffable, disassemblerOutputKind);
			}

			public void Dispose() => sourceCodeProvider.Dispose();
		}

		static Formatter CreateFormatter(Iced.Intel.ISymbolResolver symbolResolver, bool diffable, DisassemblerOutputKind disassemblerOutputKind) {
			Formatter formatter;
			switch (disassemblerOutputKind) {
			case DisassemblerOutputKind.Masm:
				formatter = new MasmFormatter(symbolResolver);
				formatter.Options.MasmAddDsPrefix32 = false;
				break;

			case DisassemblerOutputKind.Nasm:
				formatter = new NasmFormatter(symbolResolver);
				break;

			case DisassemblerOutputKind.Gas:
				formatter = new GasFormatter(symbolResolver);
				break;

			case DisassemblerOutputKind.Intel:
				formatter = new IntelFormatter(symbolResolver);
				break;

			default:
				throw new ArgumentOutOfRangeException(nameof(disassemblerOutputKind));
			}
			formatter.Options.FirstOperandCharIndex = 8;
			formatter.Options.MemorySizeOptions = MemorySizeOptions.Minimal;
			formatter.Options.ShowBranchSize = !diffable;

			return formatter;
		}

		static void Disassemble(DisasmJobContext context, DisasmJob job) {
			var (writer, disposeWriter) = job.GetTextWriter();
			try {
				var methods = job.Methods;
				Array.Sort(methods, SortMethods);
				for (int i = 0; i < methods.Length; i++) {
					if (i > 0)
						writer.WriteLine();

					var method = methods[i];
					context.Disassembler.Disassemble(context.Formatter, writer, method);
				}
			}
			finally {
				if (disposeWriter)
					writer.Dispose();
			}
		}

		// Sorted by name, except if names match, in which case the tokens are also compared
		static int SortMethods(DisasmInfo x, DisasmInfo y) {
			int c;
			c = StringComparer.Ordinal.Compare(x.TypeFullName, y.TypeFullName);
			if (c != 0)
				return c;
			c = x.TypeToken.CompareTo(y.TypeToken);
			if (c != 0)
				return c;
			c = StringComparer.Ordinal.Compare(x.MethodName, y.MethodName);
			if (c != 0)
				return c;
			c = StringComparer.Ordinal.Compare(x.MethodFullName, y.MethodFullName);
			if (c != 0)
				return c;
			return x.MethodToken.CompareTo(y.MethodToken);
		}

		static DisasmJob[] GetJobs(DisasmInfo[] methods, string outputDir, FileOutputKind fileOutputKind, FilenameFormat filenameFormat, out string? baseDir) {
			FilenameProvider filenameProvider;
			var jobs = new List<DisasmJob>();

			switch (fileOutputKind) {
			case FileOutputKind.Stdout:
				baseDir = null;
				return new[] { new DisasmJob(() => (Console.Out, false), methods) };

			case FileOutputKind.OneFile:
				if (string.IsNullOrEmpty(outputDir))
					throw new ApplicationException("Missing filename");
				baseDir = Path.GetDirectoryName(outputDir);
				return new[] { new DisasmJob(() => (File.CreateText(outputDir), true), methods) };

			case FileOutputKind.OneFilePerType:
				if (string.IsNullOrEmpty(outputDir))
					throw new ApplicationException("Missing output dir");
				baseDir = outputDir;
				filenameProvider = new FilenameProvider(filenameFormat, baseDir, DASM_EXT);
				var types = new Dictionary<int, List<DisasmInfo>>();
				foreach (var method in methods) {
					if (!types.TryGetValue(method.TypeToken, out var typeMethods))
						types.Add(method.TypeToken, typeMethods = new List<DisasmInfo>());
					typeMethods.Add(method);
				}
				var allTypes = new List<List<DisasmInfo>>(types.Values);
				allTypes.Sort((a, b) => StringComparer.Ordinal.Compare(a[0].TypeFullName, b[0].TypeFullName));
				foreach (var typeMethods in allTypes) {
					int token = typeMethods[0].TypeToken;
					var name = GetTypeName(typeMethods[0].TypeFullName);
					var getTextWriter = CreateGetTextWriter(filenameProvider.GetFilename(token, name));
					jobs.Add(new DisasmJob(getTextWriter, typeMethods.ToArray()));
				}
				return jobs.ToArray();

			case FileOutputKind.OneFilePerMethod:
				if (string.IsNullOrEmpty(outputDir))
					throw new ApplicationException("Missing output dir");
				baseDir = outputDir;
				filenameProvider = new FilenameProvider(filenameFormat, baseDir, DASM_EXT);
				foreach (var method in methods) {
					int token = method.MethodToken;
					var name = method.MethodName.Replace('.', '_');
					var getTextWriter = CreateGetTextWriter(filenameProvider.GetFilename(token, name));
					jobs.Add(new DisasmJob(getTextWriter, new[] { method }));
				}
				return jobs.ToArray();

			default:
				throw new InvalidOperationException();
			}
		}

		static readonly char[] typeSeps = new[] { '.', '+' };
		static string GetTypeName(string fullname) {
			int index = fullname.LastIndexOfAny(typeSeps);
			if (index >= 0)
				fullname = fullname[(index + 1)..];
			return fullname;
		}

		static Func<(TextWriter writer, bool close)> CreateGetTextWriter(string filename) =>
			() => (File.CreateText(filename), true);

		static (int bitness, DisasmInfo[] methods, KnownSymbols knownSymbols) GetMethodsToDisassemble(int pid, string moduleName, MemberFilter typeFilter, MemberFilter methodFilter, bool heapSearch) {
			var methods = new List<DisasmInfo>();
			var knownSymbols = new KnownSymbols();
			int bitness;
			using (var dataTarget = DataTarget.AttachToProcess(pid, true)) {
				if (dataTarget.ClrVersions.Length == 0)
					throw new ApplicationException("Couldn't find CLR/CoreCLR");
				if (dataTarget.ClrVersions.Length > 1)
					throw new ApplicationException("Found more than one CLR/CoreCLR");
				var clrInfo = dataTarget.ClrVersions[0];
				var clrRuntime = clrInfo.CreateRuntime();
				bitness = dataTarget.DataReader.PointerSize * 8;

				var module = clrRuntime.EnumerateModules().FirstOrDefault(a =>
					StringComparer.OrdinalIgnoreCase.Equals(a.Name, moduleName) ||
					StringComparer.OrdinalIgnoreCase.Equals(Path.GetFileNameWithoutExtension(a.Name), moduleName) ||
					StringComparer.OrdinalIgnoreCase.Equals(a.AssemblyName, moduleName));
				if (module is null)
					throw new ApplicationException($"Couldn't find module '{moduleName}'");

				module.AppDomain.Runtime.FlushCachedData();

				foreach (var type in EnumerateTypes(module, heapSearch)) {
					if (!typeFilter.IsMatch(type.Name, type.MetadataToken))
						continue;
					foreach (var method in type.Methods) {
						if (!IsSameType(method.Type, type))
							continue;
						if (method.CompilationType == MethodCompilationType.None)
							continue;
						if (!methodFilter.IsMatch(method.Name, method.MetadataToken))
							continue;
						var disasmInfo = CreateDisasmInfo(dataTarget, method);
						DecodeInstructions(knownSymbols, clrRuntime, disasmInfo);
						methods.Add(disasmInfo);
					}
				}
			}
			return (bitness, methods.ToArray(), knownSymbols);
		}

		static bool IsSameType(ClrType a, ClrType b) => a.Module == b.Module && a.MetadataToken == b.MetadataToken;

		static IEnumerable<ClrType> EnumerateTypes(ClrModule module, bool heapSearch) {
			var types = new HashSet<ClrType>();
			foreach (var type in EnumerateTypesCore(module, heapSearch)) {
				if (types.Add(type))
					yield return type;
			}
		}

 		/// <summary>
        /// Enumerates types with constructed method tables in all modules.
        /// </summary>
        /// <param name="heap"></param>
        /// <returns></returns>
        public static IEnumerable<ClrType> EnumerateTypes(this ClrHeap heap)
        {
            if (heap is null)
                throw new ArgumentNullException(nameof(heap));

            // The ClrHeap actually doesn't know anything about 'types' in the strictest sense, that's
            // all tracked by the runtime.  First, grab the runtime object:

            var runtime = heap.Runtime;

            // Now we loop through every module and grab every constructed MethodTable
            foreach (var module in runtime.EnumerateModules())
            {
                foreach ((ulong mt, int _) in  module.EnumerateTypeDefToMethodTableMap())
                {
                    // Now try to construct a type for mt.  This may fail if the type was only partially
                    // loaded, dump inconsistency, and in some odd corner cases like transparent proxies:
                    var type = runtime.GetTypeByMethodTable(mt);

                    if (type != null)
                        yield return type;
                }
            }
        }

		static IEnumerable<ClrType> EnumerateTypesCore(ClrModule module, bool heapSearch) {
			var runtime = module.AppDomain.Runtime;
			foreach (var type in runtime.Heap.EnumerateTypes())
				yield return type;

			if (heapSearch) {
				foreach (var obj in runtime.Heap.EnumerateObjects()) {
					var type = obj.Type;
					if (type?.Module == module)
						yield return type;
				}
			}
		}

		// Decode everything on one thread to get possible symbol values. Could be sped up of we use parallel for
		// then on the main thread, we use CLRMD (not thread safe), and then parallel for to disassemble them.
		static void DecodeInstructions(KnownSymbols knownSymbols, ClrRuntime runtime, DisasmInfo disasmInfo) {
			if (runtime.DataTarget is null) throw new NullReferenceException(nameof(runtime.DataTarget));
			var pointerSize = runtime.DataTarget.DataReader.PointerSize;
			var instrs = disasmInfo.Instructions;
			foreach (var info in disasmInfo.Code) {
				var reader = new ByteArrayCodeReader(info.Code);
				var decoder = Decoder.Create(pointerSize * 8, reader);
				decoder.IP = info.IP;
				while (reader.CanReadByte) {
					ref var instr = ref instrs.AllocUninitializedElement();
					decoder.Decode(out instr);
					int opCount = instr.OpCount;
					var symFlags = AddSymbolFlags.None;
					if (opCount == 1) {
						switch (instr.Code) {
						case Code.Call_rm32:
						case Code.Call_rm64:
						case Code.Jmp_rm32:
						case Code.Jmp_rm64:
							symFlags |= AddSymbolFlags.CallMem | AddSymbolFlags.CanBeMethod;
							break;
						}
					}
					for (int j = 0; j < opCount; j++) {
						switch (instr.GetOpKind(j)) {
						case OpKind.NearBranch16:
						case OpKind.NearBranch32:
						case OpKind.NearBranch64:
							AddSymbol(knownSymbols, runtime, instr.NearBranchTarget, symFlags | AddSymbolFlags.CanBeMethod);
							break;

						case OpKind.FarBranch16:
						case OpKind.FarBranch32:
							break;

						case OpKind.Immediate32:
							if (pointerSize == 4)
								AddSymbol(knownSymbols, runtime, instr.GetImmediate(j), symFlags | AddSymbolFlags.CanBeMethod);
							break;

						case OpKind.Immediate64:
							AddSymbol(knownSymbols, runtime, instr.GetImmediate(j), symFlags | AddSymbolFlags.CanBeMethod);
							break;

						case OpKind.Immediate16:
						case OpKind.Immediate8to16:
						case OpKind.Immediate8to32:
						case OpKind.Immediate8to64:
						case OpKind.Immediate32to64:
							AddSymbol(knownSymbols, runtime, instr.GetImmediate(j), symFlags);
							break;

						// case OpKind.Memory64:
						// 	AddSymbol(knownSymbols, runtime, instr.MemoryDisplacement64, symFlags);
						// 	break;

						case OpKind.Memory:
							if (instr.IsIPRelativeMemoryOperand)
								AddSymbol(knownSymbols, runtime, instr.IPRelativeMemoryAddress, symFlags);
							else {
								switch (instr.MemoryDisplSize) {
								case 4:
									if (pointerSize == 4)
										AddSymbol(knownSymbols, runtime, instr.MemoryDisplacement32, symFlags);
									break;

								case 8:
									AddSymbol(knownSymbols, runtime, (ulong)(int)instr.MemoryDisplacement64, symFlags);
									break;
								}
							}
							break;
						}
					}
				}
			}
		}

		[Flags]
		enum AddSymbolFlags {
			None,
			CallMem = 1,
			CanBeMethod = 2,
		}

		static void AddSymbol(KnownSymbols knownSymbols, ClrRuntime runtime, ulong address, AddSymbolFlags flags) {
			if (address < MIN_ADDR)
				return;
			if (knownSymbols.IsBadOrKnownSymbol(address))
				return;
			if (TryGetSymbolCore(runtime, address, flags, out var symbol))
				knownSymbols.Add(address, symbol);
			else
				knownSymbols.Bad(address);
		}

		static bool TryGetSymbolCore(ClrRuntime runtime, ulong address, AddSymbolFlags flags, out SymbolResult result) {
			if (address < MIN_ADDR) {
				result = default;
				return false;
			}

			if (runtime.DataTarget is null) throw new NullReferenceException(nameof(runtime.DataTarget));

			string? name;

			name = runtime.GetJitHelperFunctionName(address);
			if (!(name is null)) {
				result = new SymbolResult(address, name, FormatterTextKind.Function);
				return true;
			}

			name = runtime.DacLibrary.SOSDacInterface.GetMethodTableName(address);
			if (!(name is null)) {
				result = new SymbolResult(address, "methodtable(" + name + ")", FormatterTextKind.Data);
				return true;
			}

			var method = runtime.GetMethodByInstructionPointer(address);
			if (method is null && (address & ((uint)runtime.DataTarget.DataReader.PointerSize - 1)) == 0 && (flags & AddSymbolFlags.CallMem) != 0) {
				if (runtime.DataTarget.DataReader.ReadPointer(address, out ulong newAddress) && newAddress >= MIN_ADDR)
					method = runtime.GetMethodByInstructionPointer(newAddress);
			}
			if (!(method is null) && (flags & AddSymbolFlags.CanBeMethod) == 0) {
				// There can be data at the end of the method, after the code. Don't return a method symbol.
				//		vdivsd    xmm2,xmm2,[Some.Type.Method(Double)]	; wrong
				var info = method.HotColdInfo;
				bool isCode = ((address - info.HotStart) < info.HotSize) || ((address - info.ColdStart) < info.ColdSize);
				if (!isCode)
					method = null;
			}
			if (!(method is null)) {
				result = new SymbolResult(address, method.ToString() ?? "???", FormatterTextKind.Function);
				return true;
			}

			result = default;
			return false;
		}

		static DisasmInfo CreateDisasmInfo(DataTarget dataTarget, ClrMethod method) {
			var info = new DisasmInfo(method.Type.MetadataToken, method.Type.Name ?? "", method.MetadataToken, method.ToString() ?? "???", method.Name ?? "", method.Type.Module?.AssemblyName, CreateILMap(method.ILOffsetMap.ToArray()));
			var codeInfo = method.HotColdInfo;
			ReadCode(dataTarget, info, codeInfo.HotStart, codeInfo.HotSize);
			ReadCode(dataTarget, info, codeInfo.ColdStart, codeInfo.ColdSize);
			return info;
		}

		static ILMap[] CreateILMap(ILToNativeMap[] map) {
			var result = new ILMap[map.Length];
			for (int i = 0; i < result.Length; i++) {
				ref var m = ref map[i];
				result[i] = new ILMap {
					ilOffset = m.ILOffset,
					nativeStartAddress = m.StartAddress,
					nativeEndAddress = m.EndAddress,
				};
			}
			Array.Sort(result, (a, b) => {
				int c = a.nativeStartAddress.CompareTo(b.nativeStartAddress);
				if (c != 0)
					return c;
				return a.nativeEndAddress.CompareTo(b.nativeEndAddress);
			});

			return result;
		}

		static void ReadCode(DataTarget dataTarget, DisasmInfo info, ulong startAddr, uint size) {
			if (startAddr == 0 || size == 0)
				return;
			var code = new byte[(int)size];
			if (dataTarget.DataReader.Read(startAddr, code) != code.Length)
				throw new ApplicationException($"Couldn't read process memory @ 0x{startAddr:X}");
			info.Code.Add(new NativeCode(startAddr, code));
		}
	}
}
