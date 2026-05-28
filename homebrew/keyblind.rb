class Keyblind < Formula
  desc "Encrypted secrets vault that blinds AI agents to your API keys"
  homepage "https://keyblind.dev"
  url "https://registry.npmjs.org/keyblind/-/keyblind-0.4.0.tgz"
  sha256 "464267d6f2032517a7c22bf12b421ea5b262c8a33f111082548331742f2dafba"
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
