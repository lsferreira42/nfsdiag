AC_INIT([nfsdiag], m4_esyscmd_s([cat VERSION]))
AC_CONFIG_SRCDIR([src/nfsdiag.h])

AC_PROG_CC

# libtirpc via pkg-config, with the same fallback the Makefile has used.
TIRPC_CFLAGS=`pkg-config --cflags libtirpc 2>/dev/null`
TIRPC_LIBS=`pkg-config --libs libtirpc 2>/dev/null`
test -n "$TIRPC_CFLAGS" || TIRPC_CFLAGS="-I/usr/include/tirpc"
test -n "$TIRPC_LIBS" || TIRPC_LIBS="-ltirpc"
AC_SUBST([TIRPC_CFLAGS])
AC_SUBST([TIRPC_LIBS])

# --enable-ebpf: auto (on if clang+bpftool+libbpf found), yes (force), no (off)
AC_ARG_ENABLE([ebpf],
  [AS_HELP_STRING([--enable-ebpf], [build eBPF/libbpf performance checks (default: auto)])],
  [enable_ebpf=$enableval], [enable_ebpf=auto])

ENABLE_EBPF=0
EBPF_CPPFLAGS=""
BPF_CFLAGS=""
BPF_LIBS=""
BPFTOOL=""
CLANG=""
BPF_TARGET_ARCH=""

if test "x$enable_ebpf" != "xno"; then
  AC_CHECK_PROG([BPFTOOL], [bpftool], [bpftool])
  AC_CHECK_PROG([CLANG], [clang], [clang])
  BPF_CFLAGS=`pkg-config --cflags libbpf 2>/dev/null`
  BPF_LIBS=`pkg-config --libs libbpf 2>/dev/null`
  if test -n "$BPFTOOL" && test -n "$CLANG" && test -n "$BPF_LIBS"; then
    ENABLE_EBPF=1
    EBPF_CPPFLAGS="-DNFSDIAG_ENABLE_EBPF"
    case `uname -m` in
      x86_64)  BPF_TARGET_ARCH=x86 ;;
      aarch64) BPF_TARGET_ARCH=arm64 ;;
      *)       BPF_TARGET_ARCH=x86 ;;
    esac
    AC_MSG_NOTICE([eBPF checks enabled (libbpf + clang + bpftool found)])
  else
    if test "x$enable_ebpf" = "xyes"; then
      AC_MSG_ERROR([--enable-ebpf needs clang, bpftool and libbpf (pkg-config). Install them or pass --disable-ebpf.])
    fi
    AC_MSG_WARN([eBPF checks disabled: need clang, bpftool and libbpf])
  fi
fi

AC_SUBST([ENABLE_EBPF])
AC_SUBST([EBPF_CPPFLAGS])
AC_SUBST([BPF_CFLAGS])
AC_SUBST([BPF_LIBS])
AC_SUBST([BPFTOOL])
AC_SUBST([CLANG])
AC_SUBST([BPF_TARGET_ARCH])

AC_CONFIG_FILES([config.mk])
AC_OUTPUT
