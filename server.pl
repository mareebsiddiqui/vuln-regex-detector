#!/usr/bin/perl

use HTTP::Daemon;
use HTTP::Status;
 
my $d = HTTP::Daemon->new(
    LocalAddr => 'localhost',
    LocalPort => 4444,
) || die;

print "Listening: <URL:", $d->url, ">\n";

while (my $c = $d->accept) {
    while (my $r = $c->get_request) {
    if ($r->method eq 'GET' and $r->uri->path eq "/xyzzy") {
        $r = HTTP::Response->parse("working");
        $c->send_response($r);
    }
    else {
        $c->send_error(RC_FORBIDDEN)
    }
    }
    $c->close;
    undef($c);
}