#!/usr/bin/perl
{
package MyWebServer;
 
use HTTP::Server::Simple::CGI;
use base qw(HTTP::Server::Simple::CGI);
use CGI qw(:standard);

require "./bin/check-regex.pl";

my %dispatch = (
    '/validate' => \&validate,
);
 
sub handle_request {
    my $self = shift;
    my $cgi  = shift;
   
    my $path = $cgi->path_info();
    my $handler = $dispatch{$path};
 
    if (ref($handler) eq "CODE") {
        print "HTTP/1.0 200 OK\r\n";
        $handler->($cgi);
         
    } else {
        print "HTTP/1.0 404 Not found\r\n";
        print $cgi->header,
              $cgi->start_html('Not found'),
              $cgi->h1('Not found'),
              $cgi->end_html;
    }
}
 
sub validate {
    my $cgi  = shift;   # CGI.pm object
    return if !ref $cgi;
     
    print header('application/json');

    my $regex = $cgi->param('regex');
    my $res = check_vulnerability($regex);
    print $res;
}
 
} 
 
# start the server on port 8080
MyWebServer->new(8080)->run();
