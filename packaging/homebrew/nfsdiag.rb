class Nfsdiag < Formula
  desc "Client-side NFS diagnostic tool"
  homepage "https://www.nfsdiag.org"
  url "https://github.com/lsferreira42/nfsdiag/archive/refs/tags/v0.10.0.tar.gz"
  sha256 "93cbb1295bba48f1a732c90ae358ab199ac1d22e97cc809dd8bb62c193cd08ce"
  version "0.10.0"
  license "MIT"

  depends_on "pkg-config" => :build
  depends_on "libtirpc"

  def install
    system "make", "PREFIX=#{prefix}", "install"
    man8.install "docs/nfsdiag.8" if File.exist?("docs/nfsdiag.8")
    bash_completion.install "completions/nfsdiag.bash" => "nfsdiag" if File.exist?("completions/nfsdiag.bash")
    zsh_completion.install "completions/nfsdiag.zsh" => "_nfsdiag" if File.exist?("completions/nfsdiag.zsh")
    fish_completion.install "completions/nfsdiag.fish" if File.exist?("completions/nfsdiag.fish")
  end

  test do
    system "#{bin}/nfsdiag", "--self-test"
  end
end
