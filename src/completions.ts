const COMMANDS = [
  "init", "set", "get", "list", "alias", "aliases", "unalias", "delete",
  "sandbox", "unsandbox", "run", "start", "watch",
  "backends", "backend", "install-hook", "check-secrets", "scan-secrets",
  "audit", "check", "rotate",
  "status",
  "generate", "import", "export", "doctor",
  "completions", "config",
  "help", "unlock",
];

const FLAGS: Record<string, string> = {
  "--project": "Use a project-specific vault",
  "--biometric": "Require a biometric session for MCP server",
  "--biometric-every-time": "Require biometric auth for every secret access",
  "--expired": "Check for expired secrets",
};

export function generateBash(): string {
  return `# Keyblind bash completion
_keyblind() {
  local cur prev words cword
  _init_completion || return

  if [[ $cword -eq 1 ]]; then
    COMPREPLY=($(compgen -W "${COMMANDS.join(" ")}" -- "$cur"))
    return
  fi

  local cmd="\${words[1]}"
  case "$cmd" in
    get|delete|rotate|set|alias)
      if [[ $cword -eq 2 ]]; then
        COMPREPLY=($(compgen -W "$(keyblind list 2>/dev/null | sed 's/^  - //')" -- "$cur"))
      fi
      ;;
    unalias)
      if [[ $cword -eq 2 ]]; then
        COMPREPLY=($(compgen -W "$(keyblind aliases 2>/dev/null | sed 's/^  - //' | awk '{print $1}')" -- "$cur"))
      fi
      ;;
    backend)
      if [[ $cword -eq 2 ]]; then
        COMPREPLY=($(compgen -W "$(keyblind backends 2>/dev/null | grep '✓' | awk '{print $2}')" -- "$cur"))
      fi
      ;;
    sandbox|unsandbox|watch)
      if [[ $cword -eq 2 ]]; then
        COMPREPLY=($(compgen -f -- "$cur"))
      fi
      ;;
    start)
      COMPREPLY=($(compgen -W "--biometric --biometric-every-time" -- "$cur"))
      ;;
    check)
      COMPREPLY=($(compgen -W "--expired" -- "$cur"))
      ;;
  esac
}
complete -F _keyblind keyblind
`;
}

export function generateZsh(): string {
  return `#compdef keyblind

_keyblind() {
  local -a commands
  commands=(${COMMANDS.map(c => `'${c}'`).join("\n            ")})

  _arguments -C \\
    '--project[Use a project-specific vault]:project name:' \\
    '1:command:(${COMMANDS.join(" ")})' \\
    '*::arg:->args'

  case $words[1] in
    get|delete|rotate|set|alias)
      _arguments '2:secret:($(keyblind list 2>/dev/null | sed "s/  - //"))'
      ;;
    unalias)
      _arguments '2:alias:($(keyblind aliases 2>/dev/null | sed "s/  - //" | awk "{print \\$1}"))'
      ;;
    backend)
      _arguments '2:backend:($(keyblind backends 2>/dev/null | grep "✓" | awk "{print \\$2}"))'
      ;;
    sandbox|unsandbox|watch)
      _arguments '*:file:_files'
      ;;
    start)
      _arguments '--biometric[Require biometric session]' '--biometric-every-time[Require biometric auth for every secret access]'
      ;;
    check)
      _arguments '--expired[Check expired secrets]'
      ;;
  esac
}

_keyblind
`;
}

export function generateFish(): string {
  return `# Keyblind fish completion
set -l commands ${COMMANDS.join(" ")}

complete -c keyblind -f
complete -c keyblind -n "not __fish_seen_subcommand_from $commands" -a "$commands"
complete -c keyblind -s h -l help -d "Show help"

# --project flag
complete -c keyblind -l project -d "Use a project-specific vault" -x

# Per-command completions
complete -c keyblind -n "__fish_seen_subcommand_from get delete rotate set alias" -a "(keyblind list 2>/dev/null | sed 's/  - //')"
complete -c keyblind -n "__fish_seen_subcommand_from unalias" -a "(keyblind aliases 2>/dev/null | sed 's/  - //' | awk '{print \$1}')"
complete -c keyblind -n "__fish_seen_subcommand_from backend" -a "(keyblind backends 2>/dev/null | grep '✓' | awk '{print \$2}')"
complete -c keyblind -n "__fish_seen_subcommand_from start" -a "--biometric --biometric-every-time"
complete -c keyblind -n "__fish_seen_subcommand_from check" -a "--expired"
complete -c keyblind -n "__fish_seen_subcommand_from sandbox unsandbox watch" -F
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
source <(keyblind completions zsh)`;
    case "bash":
      return `# Add to ~/.bashrc:
source <(keyblind completions bash)`;
    case "fish":
      return `# Save to fish completions:
keyblind completions fish > ~/.config/fish/completions/keyblind.fish`;
    default:
      return `Unknown shell: ${shell}`;
  }
}
