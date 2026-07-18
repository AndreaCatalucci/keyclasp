const COMMANDS = [
  "init", "set", "get", "list", "alias", "aliases", "unalias", "delete",
  "sandbox", "unsandbox", "run", "watch",
  "backends", "backend", "install-hook", "check-secrets", "scan-secrets",
  "audit", "check", "rotate",
  "status",
  "generate", "import", "export", "doctor",
  "completions", "config",
  "help", "version",
];

const FLAGS: Record<string, string> = {
  "--project": "Use a project-specific vault",
  "--version": "Show Keyclasp version",
  "--expired": "Check for expired secrets",
};

export function generateBash(): string {
  return `# Keyclasp bash completion
_keyclasp() {
  local cur prev words cword
  _init_completion || return

  if [[ $cword -eq 1 ]]; then
    COMPREPLY=($(compgen -W "${COMMANDS.join(" ")} --version -v --help -h" -- "$cur"))
    return
  fi

  local cmd="\${words[1]}"
  case "$cmd" in
    get|delete|rotate|set|alias)
      if [[ $cword -eq 2 ]]; then
        COMPREPLY=($(compgen -W "$(keyclasp list 2>/dev/null | sed 's/^  - //')" -- "$cur"))
      fi
      ;;
    unalias)
      if [[ $cword -eq 2 ]]; then
        COMPREPLY=($(compgen -W "$(keyclasp aliases 2>/dev/null | sed 's/^  - //' | awk '{print $1}')" -- "$cur"))
      fi
      ;;
    backend)
      if [[ $cword -eq 2 ]]; then
        COMPREPLY=($(compgen -W "$(keyclasp backends 2>/dev/null | grep '✓' | awk '{print $2}')" -- "$cur"))
      fi
      ;;
    sandbox|unsandbox|watch)
      if [[ $cword -eq 2 ]]; then
        COMPREPLY=($(compgen -f -- "$cur"))
      fi
      ;;
    check)
      COMPREPLY=($(compgen -W "--expired" -- "$cur"))
      ;;
  esac
}
complete -F _keyclasp keyclasp
`;
}

export function generateZsh(): string {
  return `#compdef keyclasp

_keyclasp() {
  local -a commands
  commands=(${COMMANDS.map(c => `'${c}'`).join("\n            ")})

  _arguments -C \\
    '--project[Use a project-specific vault]:project name:' \\
    '--version[Show Keyclasp version]' \\
    '-v[Show Keyclasp version]' \\
    '1:command:(${COMMANDS.join(" ")})' \\
    '*::arg:->args'

  case $words[1] in
    get|delete|rotate|set|alias)
      _arguments '2:secret:($(keyclasp list 2>/dev/null | sed "s/  - //"))'
      ;;
    unalias)
      _arguments '2:alias:($(keyclasp aliases 2>/dev/null | sed "s/  - //" | awk "{print \\$1}"))'
      ;;
    backend)
      _arguments '2:backend:($(keyclasp backends 2>/dev/null | grep "✓" | awk "{print \\$2}"))'
      ;;
    sandbox|unsandbox|watch)
      _arguments '*:file:_files'
      ;;
    check)
      _arguments '--expired[Check expired secrets]'
      ;;
  esac
}

_keyclasp
`;
}

export function generateFish(): string {
  return `# Keyclasp fish completion
set -l commands ${COMMANDS.join(" ")}

complete -c keyclasp -f
complete -c keyclasp -n "not __fish_seen_subcommand_from $commands" -a "$commands"
complete -c keyclasp -s h -l help -d "Show help"
complete -c keyclasp -s v -l version -d "Show Keyclasp version"

# --project flag
complete -c keyclasp -l project -d "Use a project-specific vault" -x

# Per-command completions
complete -c keyclasp -n "__fish_seen_subcommand_from get delete rotate set alias" -a "(keyclasp list 2>/dev/null | sed 's/  - //')"
complete -c keyclasp -n "__fish_seen_subcommand_from unalias" -a "(keyclasp aliases 2>/dev/null | sed 's/  - //' | awk '{print \$1}')"
complete -c keyclasp -n "__fish_seen_subcommand_from backend" -a "(keyclasp backends 2>/dev/null | grep '✓' | awk '{print \$2}')"
complete -c keyclasp -n "__fish_seen_subcommand_from check" -a "--expired"
complete -c keyclasp -n "__fish_seen_subcommand_from sandbox unsandbox watch" -F
`;
}

export function detectShell(): "bash" | "zsh" | "fish" | null {
  const shell = process.env.SHELL || "";
  if (shell.includes("zsh")) return "zsh";
  if (shell.includes("bash")) return "bash";
  if (shell.includes("fish")) return "fish";
  return null;
}

export function getInstallInstructions(shell: string): string {
  switch (shell) {
    case "zsh":
      return `# Add to ~/.zshrc:
source <(keyclasp completions zsh)`;
    case "bash":
      return `# Add to ~/.bashrc:
source <(keyclasp completions bash)`;
    case "fish":
      return `# Save to fish completions:
keyclasp completions fish > ~/.config/fish/completions/keyclasp.fish`;
    default:
      return `Unknown shell: ${shell}`;
  }
}
