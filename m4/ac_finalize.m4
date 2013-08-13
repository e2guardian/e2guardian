AC_DEFUN([AC_FINALIZE_VAR], [
  test "x$prefix" = xNONE && prefix="$ac_default_prefix"
   test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
   ifelse($2, ,[:],$1=$2)
   $1=`eval echo [$]$1`
   $1=`eval echo [$]$1`
 ])
