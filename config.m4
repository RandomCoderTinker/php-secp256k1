PHP_ARG_ENABLE(secp256k1, whether to enable secp256k1 support,
[ --enable-secp256k1    Enable secp256k1 cryptographic functions ])

if test "$PHP_SECP256K1" != "no"; then
  AC_CHECK_HEADER([secp256k1.h],[have_secp=1])
  if test "$have_secp" = "1"; then
    PHP_NEW_EXTENSION(secp256k1_php, secp256k1.c, $ext_shared)
    AC_DEFINE(HAVE_SECP256K1,1,[Whether libsecp256k1 is installed])
  fi
fi
