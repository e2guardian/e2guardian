#!/usr/bin/perl

$allow_html_code = 0;
&ReadEnvs;

$deniedurl = $in{'DENIEDURL'};
$reason = $in{'REASON'};
$user = $in{'USER'};
$ip = $in{'IP'};
$cats = $in{'CATEGORIES'};

# originating hostname - can be undefined
$host = $in{'HOST'};

# virus/filter bypass hashes
# if bypass modes have been set to > 0,
# then the GBYPASS or GIBYPASS variable will contain the filter/infection bypass hash.
# if bypass modes have been set to -1,
# then the HASH variable will be set to 1 if the CGI should generate a GBYPASS hash (filter bypass),
# or 2 if the CGI should generate a GIBYPASS hash (infection bypass).

$fbypasshash = $in{'GBYPASS'}; # filter bypass hash - can be undefined
$ibypasshash = $in{'GIBYPASS'}; # infection bypass hash - can be undefined
$hashflag = $in{'HASH'}; # hash flag - can be undefined; 1 = generate GBYPASS; 2 = generate GIBYPASS


print "Content-type: text/html\n\n";
print '<HTML><HEAD><TITLE>DansGuardian - Access Denied</TITLE></HEAD>';
print '<BODY><CENTER><H2>ACCESS HAS BEEN DENIED</H2>';
if (length($user) > 0) {
  print "<br><em>$user</em>, access to the page:<P>";
}
else {
  print '<br>Access to the page:<P>';
}
print "<strong><a href=\"$deniedurl\">$deniedurl</a></strong>";
print '<P>... has been denied for the following reason:<P>';
print "<strong><font color=\"#ff0000\">$reason</font></strong>";
if (length($cats) > 0) {
  print '<P>Categories:<P>';
  print "<strong><font color=\"#ff0000\">$cats</font></strong>";
}
print '<P>Your username, IP address, date, time and URL have been logged.';
print '<P><table border=1 bgcolor="#FFEE00"><tr><td>You are seeing this error because the page you attempted<br>';
print 'to access contains, or is labelled as containing, material that';
print '<br>has been deemed inappropriate.</td></tr></table>';
print '<P><table border=1 bgcolor="#44dd44"><tr><td>If you have any queries contact your ICT Co-ordinator or Network Manager.</td></tr></table>';
print '<P><font size=-3>Powered by <a href="http://dansguardian.org" target="_blank">DansGuardian</a></font>';
print '</center></BODY></HTML>';

exit;





sub ReadEnvs {
  local($cl, @clp, $pair, $name, $value);
  if ( $ENV{'REQUEST_METHOD'} eq 'POST' ) {
    read(STDIN, $cl, $ENV{'CONTENT_LENGTH'} );
  }
  else {
    $cl = $ENV{'QUERY_STRING'};
  }
  @clp = split(/::/, $cl);
  foreach $pair (@clp) {
    ($name, $value) = split(/==/, $pair);
    $value =~ tr/+/ /;
    $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
    $value =~ s/<!--(.|\n)*-->//g;
    if ($allow_html_code != 1) {
      $value =~ s/<([^>]|\n)*>//g;
    }
    $in{$name} = $value;
  }
}




