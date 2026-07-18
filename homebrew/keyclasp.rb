class Keyclasp < Formula
  desc "Runtime secrets for coding agents"
  homepage "https://github.com/AndreaCatalucci/keyclasp"
  head "https://github.com/AndreaCatalucci/keyclasp.git", branch: "main"
  license "MIT"

  depends_on "node"

  def install
    system "npm", "install"
    system "npm", "run", "build"
    libexec.install Dir["*"]
    bin.install_symlink libexec/"dist/cli.js" => "keyclasp"
  end

  test do
    assert_match "Keyclasp", shell_output("#{bin}/keyclasp --help")
  end
end
