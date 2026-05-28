class Keyblind < Formula
  desc "Encrypted secrets vault that blinds AI agents to your API keys"
  homepage "https://keyblind.dev"
  url "https://registry.npmjs.org/keyblind/-/keyblind-0.2.2.tgz"
  sha256 "5375fb93590577af4b6b5b7962188660862962ed"
  license "MIT"

  depends_on "node"

  def install
    system "npm", "install", "--global", "--prefix", prefix, buildpath
    # Remove symlink and install into libexec
    libexec.install Dir["*"]
    bin.install_symlink libexec/"bin/keyblind"
  end

  test do
    assert_match "Keyblind", shell_output("#{bin}/keyblind --help")
  end
end
