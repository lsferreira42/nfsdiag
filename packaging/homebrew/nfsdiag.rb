class Nfsdiag < Formula
  desc "Client-side NFS diagnostic tool"
  homepage "https://www.nfsdiag.org"
  url "https://github.com/lsferreira42/nfsdiag/archive/refs/tags/v0.10.1.tar.gz"
  sha256 "40c3860e6e8e2e9f2a61c93d12c0a9db83aaf7af1b9b2505d4aa1ec2a63c1cf3"
  version "0.10.1"
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
