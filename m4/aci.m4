dnl
dnl ACI (autoconf interactif) mechanism. 
dnl  for now, it's not interactif, but one day, the user will be able to
dnl  select which packages he wants from the available list
dnl

dnl Copyright (C) 2000,2001 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY, to the extent permitted by law; without
dnl even the implied warranty of MERCHANTABILITY or FITNESS FOR A
dnl PARTICULAR PURPOSE.

dnl History:
dnl  one day, I'll do a public release. Until then, check the FAST changelogs.

dnl ACI_D: echo something to the config.log
AC_DEFUN([ACI_D],[echo $1>&5;])dnl >&5

dnl ACI_PACKAGE: defines a package (ie, an external package we should search)
dnl SYNOPSIS:
dnl  1=Package (name of the package)
dnl  2=Description (human readable, for documentation)
dnl  3=Function (the main function to search)
dnl  4=Library list (where to search, space separated list of group of LDFLAGS
dnl                  each LDFLAGS is ! separated.
dnl                  example: "-lldap -lldap!-llber"
dnl                  warning: can't contain tabs or newlines)
dnl  5=Header to check
dnl  6=what to do if found
dnl  7=what to do if not found (default: AC_MSG_ERROR(blabla))
dnl  It is possible to change any of the exported values in $6 or $7
dnl ACTIONS:
dnl  - try to find the function in each part of LDFLAGS and the header.
dnl  - AC_SUBST the following values:
dnl    HAVE_$1:   'yes' or 'no'
dnl    CFLAGS_$1: CFLAGS to acces to this package
dnl    LIBS_$1:   LDFLAGS to acces to this package
dnl  - define the following arguments to ./configure:
dnl    --with-$1          root dir of install
dnl    --with-$1-includes where to search the header
dnl    --with-$1-libs     where to search the libs
dnl    --with-$1-extra    extra LDFLAGS to pass to the linker
AC_DEFUN([ACI_PACKAGE],[
  	pushdef([aci_name],        [$1])
        pushdef([aci_help],        [$2])
  	pushdef([aci_func],        [$3])
  	pushdef([aci_paths],       [$4])
  	pushdef([aci_header],      [$5])
	pushdef([aci_if_yes],      [$6])
	pushdef([aci_if_no],       [$7])
	
	ACI_D("[BEGINING OF ACI-PACKAGE($1,$2,$3,$4,$5,$6,$7]")
        aci_module_desc_$1="$2"
        aci_packages="$aci_packages $1"

        dnl
	dnl Specify the options
        dnl
	AC_ARG_WITH([$1],
          AC_HELP_STRING([--with-$1=DIR],
	    [root directory of aci_help installation]),
	  [with_$1=$withval
	   good=yes
	   if test "$withval" = yes ; then good=no; fi
	   if test "$withval" = no ; then good=no; fi
	   if test $good = no ; then
             AC_MSG_ERROR([You gave me --with-$1=$withval. I wait for a location[,] not yes or no (use --enable-[]aci_help or --disable-[]aci_help for that)])
	   fi
	   CFLAGS_$1="-I$withval/include $CFLAGS_$1"
	   LIBS_$1="-L$withval/lib $LIBS_$1"
	  ])
	
	AC_ARG_WITH([$1-includes],
          AC_HELP_STRING([--with-$1-includes=DIR],
            [specify exact include dir for aci_help headers]),
          [CFLAGS_$1="-I$withval $CFLAGS_$1"])
	
	AC_ARG_WITH([$1-libdir],
          AC_HELP_STRING([--with-$1-libdir=DIR],
	     [specify exact library dir for aci_help library]
          ),[LIBS_$1="-L$withval $LIBS_$1"])

	AC_ARG_WITH([$1-extra],
          AC_HELP_STRING([--with-$1-extra=ARG],
	     [specify extra args to pass to the linker to get the aci_help library]
          ),[LIBS_$1="$withval $LIBS_$1"])
	
        dnl
        dnl Search the lib
        dnl
	OLD_LDFLAGS=$LDFLAGS
	OLD_CFLAGS=$CFLAGS
	OLD_CPPFLAGS=$CPPFLAGS
	
        dnl make sure there is no newline in paths
        i=`echo aci_paths|wc -l`
        if test $i != 1 && test $i != 0 ; then
          AC_MSG_ERROR([Badly formed args for function ACI-PACKAGE.
            please no newline and no tab.])
        fi

        ac_func_search_save_LIBS="$LIBS"
        ac_func_search_save_this_LIBS="$LIBS_$1"
        aci_found="no"
        AC_MSG_CHECKING([for aci_name. Can I access aci_func without new libs])
        AC_TRY_LINK_FUNC(aci_func, 
                         [AC_MSG_RESULT([yes])
                          aci_found="yes"],
                         [AC_MSG_RESULT([no])] )
        for i in aci_paths
        do
          if test "$aci_found" = "no"; then
            LIBS_$1=`echo "$i $ac_func_search_save_this_LIBS"|sed 's/!/ /g'`
            LIBS="$LIBS_$1 $ac_func_search_save_LIBS"
            AC_MSG_CHECKING([for aci_name. Can I access aci_func with $LIBS_$1])
            AC_TRY_LINK_FUNC(aci_func,aci_found="yes",aci_found="no")
            AC_MSG_RESULT($aci_found)
          fi
        done
        LIBS="$ac_func_search_save_LIBS"
 
        dnl
        dnl search for the header (only if the lib was found)
        dnl
	if test "x$aci_found" = "xyes" && test "x"aci_header != "x" ; then
          CPPFLAGS="$CPPFLAGS $CFLAGS_$1"
          ACI_D("CPPFLAGS=$CPPFLAGS")
          AC_CHECK_HEADER(aci_header,good=yes,good=no)
	fi
	if test "x$aci_found" = "xno" ; then
	dnl Something where not found.
        dnl If the caller specified what to do in this case, do it. 
        dnl Else, complain.
	   ifelse(aci_if_no, ,
                  [AC_MSG_ERROR(Can't find the package $1. Please install it[,] or if it is installed[,] tell me where with the --with-$1 argument (see ./configure --help=short).)],
		  aci_if_no)
	else
	dnl Anything where found
      		HAVE_$1="yes"
	        ifelse(aci_if_yes, , echo >/dev/null, aci_if_yes)
	fi
	if test "x$HAVE_$1" != "xyes" ; then
          CFLAGS_$1=""
          LIBS_$1=""
        fi
        dnl AC_SUBST what should be
        AC_SUBST(HAVE_$1) 
        AC_SUBST(CFLAGS_$1) 
        AC_SUBST(LIBS_$1) 

        dnl restore the old settings
	LDFLAGS=$OLDLDFLAGS
	CPPFLAGS=$OLDCPPFLAGS
	CFLAGS=$OLDCFLAGS
])

dnl ACI_PACKAGE_SAVED: same as ACI_PACKAGE, but with an external cache
dnl SYNOPSIS:
dnl  1=Package (name of the package)
dnl  2=Description (human readable, for documentation)
dnl  3=Cache program.Should accept --libs and --cflags (like gnome-config does)
dnl  4=Extra arg to pass to this prog (like a name of library)
dnl  5=what to do if found
dnl  6=what to do if not found (default AC_MSG_ERROR(blabla))
dnl ACTIONS:
dnl  - try to find the cache program
dnl  - AC_SUBST the following values:
dnl    HAVE_$1:   'yes' or 'no'
dnl    CFLAGS_$1: CFLAGS to acces to this package
dnl    LIBS_$1:   LDFLAGS to acces to this package

AC_DEFUN([ACI_PACKAGE_SAVED],[
  AC_PATH_PROG(ACI_CACHE_PROG,$3,no)
  aci_module_desc_$1="$2"
  aci_packages="$aci_packages $1"
  if test x$ACI_CACHE_PROG = xno; then
    HAVE_$1=no
    CFLAGS_$1=""
    LIBS_$1=""
    ifelse($6, ,[AC_MSG_ERROR([Cannot find $1: Is $3 in your path?])],$6)
  else
    HAVE_$1=yes
    CFLAGS_$1=`$ACI_CACHE_PROG --cflags $4`
    LIBS_$1=`$ACI_CACHE_PROG --libs $4`
    ifelse($5, ,echo >/dev/null,$5)
  fi
  dnl AC_SUBST what should be
  AC_SUBST(HAVE_$1) 
  AC_SUBST(CFLAGS_$1) 
  AC_SUBST(LIBS_$1) 
])
dnl ACI_MODULE: defines a module (ie, a part of the code we are building)
dnl  1=abbrev
dnl  2=human readable description
dnl  3=dependences (space separated list of abbrev)
dnl  4=submodules (space separated list of abbrev)
dnl  5=default ([yes]/no) (if not given, yes is assumed)
dnl  6=extra childs, which are listed under it in tree, without being a module

AC_DEFUN([ACI_MODULE],[
  aci_module_desc_$1="$2"
  aci_module_dep_$1="$3"
  aci_module_sub_$1="$4"
  aci_module_child_$1="$4 $6"
  ifelse(ifelse([$5], ,[yes],[$5]),[yes],
         dnl what to do if module is enabled by default
         [AC_ARG_ENABLE($1,
            AC_HELP_STRING([--disable-$1],
              [Disable the module $1, $2.]),
              [aci_modules_disabled="$aci_modules_disabled $1"],
              [aci_modules_possible="$aci_modules_possible $1"]
            )],
         dnl what to do if module is disabled by default
         [AC_ARG_ENABLE($1,
            AC_HELP_STRING([--enable-$1],
              [Enable the module $1, $2.]),
              [aci_modules_possible="$aci_modules_possible $1"],
              [aci_modules_disabled="$aci_modules_disabled $1"]
            )]
        )
])

dnl ACI_MODULES_VERIFY: verify which module can be satisfied 
dnl  (place for future interactivity)
dnl  export $1_MODULES to Makefiles, init'ed to the list of modules to build
dnl   1: the name of this group of modules

AC_DEFUN([ACI_MODULES_VERIFY],[
  dnl Check the dependencies of everyone
  for aci_module in $aci_modules_possible
  do 
    aci_mod_bad=""
    ACI_D("Look module $aci_module")
    for aci_mod_dep in `eval echo '$aci_module_dep_'"$aci_module"`
    do
      ACI_D($ECHO_N "  it depends on $aci_mod_dep...")
      if test `eval echo 'x$'"HAVE_$aci_mod_dep"` != xyes; then
          ACI_D("Not satisfied !")
	  aci_mod_bad=`echo "$aci_mod_bad $aci_mod_dep"|sed 's/^ *//'`
      else
          ACI_D("Satisfied !")
      fi
    done
    if test -z "$aci_mod_bad"; then
      ACI_D("Module $aci_module will be builded")
      ACI_D([])
      aci_modules="$aci_modules $aci_module"
      eval "HAVE_$aci_module=\"yes\""
    else
      ACI_D("Won't build $aci_module because it depends on $aci_mod_bad.")
      ACI_D([])
      eval "aci_module_misdep_$aci_module=\"$aci_mod_bad\""
      aci_modules_broken="$aci_modules_broken $aci_module"
      eval "HAVE_$aci_module=\"no\""
    fi
    eval `echo "MODULES_$aci_module=\"$aci_mod_ok\""`
  done

  dnl Build the list of submodules to build
  ACI_D("Build the submodules lists")
  for aci_module in $aci_modules_possible
  do 
    ACI_D($ECHO_N "  Look for $aci_module: ")
    for aci_mod_sub in `eval echo '$aci_module_sub_'"$aci_module"`
    do
      if test `eval echo 'x$HAVE_'"$aci_mod_sub"` = xyes; then
        ACI_D($ECHO_N "$aci_mod_sub ")
        eval "MODULES_$aci_module=\"\$MODULES_$aci_module $aci_mod_sub\""
      else
        ACI_D($ECHO_N "NOT $aci_mod_sub ")
      fi
    done
    ACI_D([])
  done
])

dnl ACI_MODULES_SUMMARY: give a summary of what will be build to user
dnl  1: Name of the root of modules (can be a space separated list)

AC_DEFUN([ACI_MODULES_SUMMARY],[
  if test "x$aci_modules" != "x"; then
    echo "The following modules will be builded: "
    for aci_module in $aci_modules 
    do
      echo "  - $aci_module: "`eval echo '$aci_module_desc_'"$aci_module"`
      if "`echo "\$MODULES_$aci_module"`" ; then
        echo "    submodules: "`eval echo "\$MODULES_$aci_module"`
      fi
    done
  else
    echo "No module will be build."
  fi
  echo

  if test "x$aci_modules_disabled" != "x"; then
    echo "The following modules are disabled, either by you or by default."
    for aci_module in $aci_modules_disabled
    do
      echo "  - $aci_module: "`eval echo '$aci_module_desc_'"$aci_module"`
    done
    echo
  fi

  if test "x$aci_modules_broken" != "x"; then
    echo "The following modules have BROKEN dependencies:"
    for aci_module in $aci_modules_broken
    do
      echo "  - $aci_module: "`eval echo '$aci_module_desc_'"$aci_module"`
      echo "    Depends on: "`eval echo '$aci_module_misdep_'"$aci_module"`
    done

    echo
    echo "  If you think I'm a dumb script, and these dependencies can be"
    echo "  satified, please try to use the --with-PACKAGE options. See:"
    echo "    ./configure --help=short"
    echo
    echo "The other modules may be build even if these ones are not."
    echo
  fi
])

AC_DEFUN([ACI_ECHO],[echo $1;echo $1>&5])

dnl ACI_MODULES_SUMMARY_FANCY: same as ACI_MODULES_SUMMARY, in a fancy way.
AC_DEFUN([ACI_MODULES_SUMMARY_FANCY],[
  # the file conftests.nexts is a file containing the modules we still have to
  # handle. Each line have the form "level nb module", defining at which
  # <level> <module> is defined. It is the <nb>th at this level
  
  ###
  # Initializations
  ###
  ACI_ECHO([])
  name="$1"
  ACI_ECHO(["Summary of the configuration for $name"])
  aci_sum_more="no"     # If there is more modules to handle
  rm -f conftest.nexts conftest.nexts.new
  
    # initialize aci_sum_nexts and aci_sum_more from the given argument
  aci_sum_nb=9
  for aci_sum_tmp in $1
  do
    echo "0 $aci_sum_nb $aci_sum_tmp" >> conftest.nexts
    aci_sum_more="yes"
    aci_sum_nb=`expr $aci_sum_nb - 1`
  done

#cat conftest.nexts
#echo "---"

  ###
  # Main loop
  ###
  while test "x$aci_sum_more" = "xyes" ; do

    # sort the list
    sort -r -k 1,3 conftest.nexts > conftest.nexts.new
    mv conftest.nexts.new conftest.nexts

    changequote(<<, >>)dnl because of the regexp [[:blank:]]

    # get the next elem to handle and its level, and remove it from the list
    aci_sum_this=`head -n 1 conftest.nexts|\
       sed -e 's/^[0-9]*[[:blank:]]*[0-9]*[[:blank:]]*\([^[:blank:]]*$\)/\1/'`
    aci_sum_lvl=`head -n 1 conftest.nexts |\
       sed -e 's/^\([0-9]*\)[[:blank:]].*$/\1/'`

#    aci_sum_this=`sed -e '1~1000s/^[0-9]*[[:blank:]]*[0-9]*[[:blank:]]*\([^[:blank:]]*$\)/\1/'\
#                      -e '2~1d'\
#                      conftest.nexts`
#    aci_sum_lvl=`sed -e '1~1000s/^\([0-9]*\)[[:blank:]].*$/\1/'\
#                      -e '2~1d'\
#                      conftest.nexts`

    tail +2l conftest.nexts > conftest.nexts.new
    mv conftest.nexts.new conftest.nexts

#echo "aci_sum_this=$aci_sum_this"
#cat conftest.nexts
#echo "---"
    # stop if nothing else to do
    if test "x$aci_sum_this" = x ; then
      aci_sum_more="no"
    else
      # Add the sub modules of this on to the file
      aci_sum_sub=`expr $aci_sum_lvl + 1`
      aci_sum_nb=9
      for aci_sum_tmp in `eval echo '$aci_module_child_'"$aci_sum_this"`
      do
        echo "$aci_sum_sub $aci_sum_nb $aci_sum_tmp" >> conftest.nexts
        aci_sum_nb=`expr $aci_sum_nb - 1`
      done

      # compute the status of this module
      if echo $aci_modules_disabled|grep -q $aci_sum_this ; then
        aci_sum_status="(DISABLED)"
      else  
        if test `eval echo '"x$aci_module_misdep_'"$aci_sum_this\""` = x ; then
          aci_sum_status="(OK)"
        else        
          aci_sum_status="(BROKEN)"
        fi
      fi

      # Outputs the title of this module
      aci_sum_header=""
      while test $aci_sum_lvl -ne 0
      do
        aci_sum_header="$aci_sum_header  "
        aci_sum_lvl=`expr $aci_sum_lvl - 1`
      done
  
      changequote([, ])dnl back to normality, there is no regexp afterward
    ACI_ECHO("$aci_sum_header"'>'" $aci_sum_this$aci_sum_status: "`eval echo '$aci_module_desc_'"$aci_sum_this"`)

      aci_sum_head_dep="$aci_sum_header    "
      aci_sum_tmp=`eval echo '$'"MODULES_$aci_sum_this"|
                   sed 's/[^[:blank:]] .*$//'`
      if test "x$aci_sum_tmp" != x ; then
        ACI_ECHO("$aci_sum_head_dep Optional submodules to build: "`eval echo '$'"MODULES_$aci_sum_this"`)
      fi
      
      
      # outputs the dependencies of this module
      aci_sum_deps=""
      aci_sum_dep_some="no"
      for aci_sum_dep in `eval echo '$aci_module_dep_'"$aci_sum_this"`
      do
        if echo $aci_packages|grep -q $aci_sum_dep ||\
           echo `eval echo '$aci_module_misdep_'"$aci_sum_this"`|grep -q $aci_sum_dep; then 
          aci_sum_deps="$aci_sum_deps $aci_sum_dep"
          aci_sum_dep_some="yes"
        fi
      done
      if test "x$aci_sum_dep_some" = xyes ; then
        ACI_ECHO("$aci_sum_head_dep Packages and modules it depends on:")
        for aci_sum_dep in $aci_sum_deps
        do
          # compute the status of this package
          if test `eval echo 'x$'"HAVE_$aci_sum_dep"` = xyes ; then
            aci_sum_pkg_status="(FOUND)"
          else  
            aci_sum_pkg_status="(NOT FOUND)"
          fi

          # output the status of this package
          ACI_ECHO("$aci_sum_head_dep  o $aci_sum_dep$aci_sum_pkg_status: "`eval echo '$aci_module_desc_'"$aci_sum_dep"`)
          aci_sum_tmp=`eval echo '$'"LIBS_$aci_sum_dep"|
                       sed 's/[^[:blank:]] .*$//'`
          if test "x$aci_sum_tmp" != x ; then
            ACI_ECHO( "$aci_sum_head_dep      LIBS:   "`eval echo '$'"LIBS_$aci_sum_dep"`)
          fi
          aci_sum_tmp=`eval echo '$'"CFLAGS_$aci_sum_dep"|
                       sed 's/[^[:blank:]] .*$//'`
          if test "x$aci_sum_tmp" != x ; then
            ACI_ECHO("$aci_sum_head_dep      CFLAGS: "`eval echo '$'"CFLAGS_$aci_sum_dep"`)
          fi
        done
      fi
    fi
    ACI_ECHO("$aci_sum_header")
  done
  if test "x$aci_modules_disabled" != "x"; then
    ACI_ECHO( "  Some modules are disabled[,] either by you or by default")
    ACI_ECHO( )
  fi
  if test "x$aci_modules_broken" != "x"; then
    ACI_ECHO( "  If you think I'm a dumb script[,] and these broken dependencies can")
    ACI_ECHO( "  be satified[,] please try to use the --with-PACKAGE options. See:")
    ACI_ECHO( "    ./configure --help=short")
    ACI_ECHO([])
    ACI_ECHO( "The other modules may be build even if these ones are not.")
    ACI_ECHO([])
  fi
  if test "x$aci_modules_disabled$aci_modules_broken" = "x"; then
    ACI_ECHO( "  Everything went well.")
  fi
])
