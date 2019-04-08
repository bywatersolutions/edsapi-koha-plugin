#!/usr/bin/perl -w

use strict;
use warnings;
use LWP::Simple;
use CGI;

my $PluginDir = C4::Context->config("pluginsdir");$PluginDir = $PluginDir.'/Koha/Plugin/EDS';require $PluginDir.'/opac/eds-methods.pl';

my $q = CGI->new;
my $an = $q->param('an');
my $dbid = $q->param('dbid');


print "Content-type: text/html\n\n";

my $uri = "https://eds-api.ebscohost.com/edsapi/rest/ExportFormat?an=" . $an . "&dbid=" . $dbid . "&format=ris";

print CallREST('GET',$uri,'', GetAuth(), GetSession());
