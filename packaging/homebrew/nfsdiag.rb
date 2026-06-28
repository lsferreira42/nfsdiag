class Nfsdiag < Formula
  desc "Client-side NFS diagnostic tool"
  homepage "https://www.nfsdiag.org"
  url "https://github.com/lsferreira42/nfsdiag/archive/refs/tags/v0.12.0.tar.gz"
  sha256 "2bf2ecc333a47c7091374f75c2a202f4aa0f7191b3953bde26a6425b4a8dfeff"
  version "0.12.0"
  license "MIT"

  # nfsdiag parses /proc and drives mount.nfs, and libtirpc is Linux-only, so
  # this formula targets Linuxbrew only; it does not build on macOS.
  depends_on :linux

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
