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

using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace JitDasm {
	enum FileOutputKind {
		Stdout,
		OneFile,
		OneFilePerType,
		OneFilePerMethod,
	}

	enum FilenameFormat {
		MemberName,
		TokenMemberName,
		Token,
	}

	enum DisassemblerOutputKind {
		Masm,
		Nasm,
		Gas,
		Intel,
	}

	sealed class JitDasmOptions {
		public int Pid;
		public string ModuleName = string.Empty;
		public string? LoadModule;
		public string OutputDir = string.Empty;
		public readonly List<string> AssemblySearchPaths = new();

		public readonly MemberFilter TypeFilter = new();
		public readonly MemberFilter MethodFilter = new();
		public bool Diffable = false;
		public bool ShowAddresses = true;
		public bool ShowHexBytes = true;
		public bool ShowSourceCode = true;
		public bool HeapSearch = false;
		public bool RunClassConstructors = true;
		public FilenameFormat FilenameFormat = FilenameFormat.MemberName;
		public FileOutputKind FileOutputKind = FileOutputKind.Stdout;
		public DisassemblerOutputKind DisassemblerOutputKind = DisassemblerOutputKind.Masm;
	}

	sealed class TokensFilter {
		readonly List<(uint lo, uint hi)> tokens = new();
		public bool HasTokens => tokens.Count != 0;
		public void Add(uint lo, uint hi) => tokens.Add((lo, hi));
		public bool IsMatch(int token) {
			foreach (var (lo, hi) in tokens) {
				if (lo <= token && token <= hi)
					return true;
			}
			return false;
		}
	}

	sealed class MemberFilter {
		public readonly RegexFilter NameFilter = new();
		public readonly TokensFilter TokensFilter = new();
		public readonly RegexFilter ExcludeNameFilter = new();
		public readonly TokensFilter ExcludeTokensFilter = new();

		public bool IsMatch(string? name, int token) {
			if (TokensFilter.HasTokens || NameFilter.HasFilters) {
				bool match =
					(TokensFilter.HasTokens && TokensFilter.IsMatch(token)) ||
					(NameFilter.HasFilters && NameFilter.IsMatch(name));
				if (!match)
					return false;
			}

			if (ExcludeTokensFilter.HasTokens || ExcludeNameFilter.HasFilters) {
				bool match =
					(ExcludeTokensFilter.HasTokens && ExcludeTokensFilter.IsMatch(token)) ||
					(ExcludeNameFilter.HasFilters && ExcludeNameFilter.IsMatch(name));
				if (match)
					return false;
			}

			return true;
		}
	}

	sealed class RegexFilter {
		readonly List<Regex> regexes = new();
		public bool HasFilters => regexes.Count != 0;
		public bool IsMatch(string? value) {
			if (value is null) return false;
			foreach (var regex in regexes) {
				if (regex.IsMatch(value))
					return true;
			}
			return false;
		}
		public void Add(string pattern) => regexes.Add(CreateRegex(pattern));
		static Regex CreateRegex(string wildcardString) {
			const RegexOptions flags = RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.Singleline;
			return new Regex("^" + Regex.Escape(wildcardString).Replace(@"\*", ".*").Replace(@"\?", ".") + "$", flags);
		}
	}
}
