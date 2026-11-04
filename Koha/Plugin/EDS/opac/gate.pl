package Koha::Plugin::EDS::OpacGate;

# Refuses requests to the OPAC scripts that no browser on an OPAC page sends, and caps how fast
# one visitor can call them. Each script runs this from a BEGIN block, before it loads Koha, so a
# refused request costs a few milliseconds instead of a Koha compile and several EDS API calls.

use strict;
use warnings;
use feature qw( state );

use constant PAGE_LIMIT => 30;     # page views per visitor per minute
use constant JSON_LIMIT => 120;    # the basket fetches one record per call
use constant WINDOW     => 60;

# Only act on a CGI request; a persistent server compiles the scripts once, outside any request
return 1 unless $ENV{GATEWAY_INTERFACE};

my ($script) = ( $ENV{SCRIPT_NAME} // q{} ) =~ m{([^/]+)\z};
my %kind = (
    'eds-raw.pl'    => 'json',
    'eds-ac.pl'     => 'json',
    'eds-cite.pl'   => 'json',
    'eds-search.pl' => 'page',
    'eds-detail.pl' => 'page',
    'pfi-search.pl' => 'page',
);
my $kind = $kind{ $script // q{} } or return 1;

my %cookie = map { /^\s*([^=]+)=(.*)$/ ? ( $1 => $2 ) : () } split /;/, $ENV{HTTP_COOKIE} // q{};
my $query  = $ENV{QUERY_STRING} // q{};

# The plugin's configure page opens these on the OPAC host from the staff interface
if ( $script eq 'eds-raw.pl' && $query =~ /(?:^|&)q=(?:getip|info)(?:&|$)/ ) {
    too_many( 'json', PAGE_LIMIT ) if over_limit( 'staff', $ENV{REMOTE_ADDR}, PAGE_LIMIT );
    return 1;
}

my ($visitor) = grep { defined && length } @cookie{qw( CGISESSID EDS_COOKIE_CHECK )};

# Where Koha's bot guard is on, these need the same trust cookie as opac-search.pl
if ( my $guard = bot_guard() ) {
    unless ( $guard->is_exempt_ip( $ENV{REMOTE_ADDR} ) ) {
        my $trust = Koha::BotGuard::TrustCookie->verify( $guard->cookie_value( \%ENV ) );
        return 1 if $trust && $trust->{kind} eq 'authenticated';

        if ($trust) {

            # One budget per trust cookie, however many sessions it is used with
            $visitor = $trust->{nonce};
        } else {
            my $refusal = $guard->refuse(
                { %ENV, PATH_INFO => $ENV{SCRIPT_NAME} },
                'challenge', undef,
                $kind eq 'page'
                ? $guard->challenge_response
                : [
                    403, [ 'Content-Type' => 'application/json', 'Cache-Control' => 'no-store' ],
                    ['{"error":"This is only available from the catalog."}']
                ]
            );
            respond_psgi($refusal) if $refusal;
        }
    }
}

if ( $kind eq 'json' ) {

    # The plugin's JavaScript calls these from an OPAC page, which always sets CGISESSID
    my $fetch_mode = $ENV{HTTP_SEC_FETCH_MODE} // q{};
    my $navigation = $fetch_mode eq 'navigate'
        || ( !$fetch_mode && !$ENV{HTTP_X_REQUESTED_WITH} && ( $ENV{HTTP_ACCEPT} // q{} ) =~ m{text/html} );
    respond( '403 Forbidden', 'application/json', '{"error":"This is only available from the catalog."}' )
        if !length( $cookie{CGISESSID} // q{} ) || $navigation;

    too_many( 'json', JSON_LIMIT ) if over_limit( 'json', $visitor, JSON_LIMIT );
    return 1;
}

unless ( defined $visitor ) {

    # A link opened in a new browser has no cookies yet, so set one and come back once to see if it sticks
    respond( '403 Forbidden', 'text/html; charset=utf-8', page('Discovery search needs cookies to be enabled.') )
        if $query =~ /(?:^|&)eds_cookie_check=1(?:&|$)/;

    my $check = sprintf '%08x%08x', int rand 2**32, int rand 2**32;
    respond(
        '302 Found', 'text/html; charset=utf-8', q{},
        "Location: $script?" . ( length $query ? "$query&" : q{} ) . 'eds_cookie_check=1',
        "Set-Cookie: EDS_COOKIE_CHECK=$check; Path=/; HttpOnly; SameSite=Lax",
    );
}

too_many( 'page', PAGE_LIMIT ) if over_limit( 'page', $visitor, PAGE_LIMIT );
return 1;

=head1 FUNCTIONS

=head2 over_limit

    my $over = over_limit( $kind, $visitor, $limit );

Counts this request against the visitor's budget in Koha's memcached and says whether it is
over $limit for the current window. Without memcached every request is allowed.

=cut

sub over_limit {
    my ( $kind, $visitor, $limit ) = @_;

    ( $visitor = $visitor // $ENV{REMOTE_ADDR} // q{} ) =~ s/[^A-Za-z0-9.:_-]//g;
    return 0 unless length $visitor;

    my $config      = koha_conf();
    my ($servers)   = $config =~ m{<memcached_servers>\s*([^<]+?)\s*</memcached_servers>} or return 0;
    my ($namespace) = $config =~ m{<memcached_namespace>\s*([^<]*?)\s*</memcached_namespace>};

    my $memcached = eval {
        require Cache::Memcached::Fast;
        Cache::Memcached::Fast->new(
            {
                servers         => [ split /\s*,\s*/, $servers ],
                namespace       => ( $namespace || 'koha' ) . ':eds_gate:',
                connect_timeout => 0.1,
                io_timeout      => 0.1,
            }
        );
    } or return 0;

    my $key   = "$kind:" . substr( $visitor, 0, 64 );
    my $count = $memcached->incr($key);
    unless ( defined $count ) {
        $memcached->add( $key, 0, WINDOW );
        $count = $memcached->incr($key);
    }
    return defined $count && $count > $limit ? 1 : 0;
}

=head2 koha_conf

    my $config = koha_conf();

The text of koha-conf.xml, read without loading Koha.

=cut

sub koha_conf {
    state $config;
    return $config if defined $config;

    $config = q{};
    if ( $ENV{KOHA_CONF} && open my $fh, '<', $ENV{KOHA_CONF} ) {
        $config = do { local $/; <$fh> };
        close $fh;
    }
    return $config;
}

=head2 bot_guard

    my $guard = bot_guard();

Koha's bot guard middleware set up from koha-conf.xml, when this Koha has one and it is on.

=cut

sub bot_guard {
    my ($block) = koha_conf() =~ m{<opac_bot_guard>(.*?)</opac_bot_guard>}s or return;
    return unless $block =~ m{<enabled>\s*1\s*</enabled>};

    my $guard = eval {
        require Koha::Middleware::BotGuard;
        my $middleware = Koha::Middleware::BotGuard->new( { app => sub { } } );
        $middleware->prepare_app;
        $middleware;
    } or return;
    return $guard->enabled ? $guard : undef;
}

=head2 respond_psgi

    respond_psgi($response);

Prints a PSGI response as a CGI response and ends the process.

=cut

sub respond_psgi {
    my ($response) = @_;
    my ( $code, $headers, $body ) = @{$response};

    require HTTP::Status;
    my @lines = ( "Status: $code " . HTTP::Status::status_message($code) );
    push @lines, "$headers->[ 2 * $_ ]: $headers->[ 2 * $_ + 1 ]" for 0 .. @{$headers} / 2 - 1;
    binmode STDOUT;
    print join( "\r\n", @lines, q{}, q{} ), @{$body};
    exit 0;
}

=head2 too_many

    too_many( $kind, $limit );

=cut

sub too_many {
    my ( $kind, $limit ) = @_;
    my $message = "Too many requests, please wait a minute and try again.";
    return $kind eq 'json'
        ? respond( '429 Too Many Requests', 'application/json', qq{{"error":"$message"}}, 'Retry-After: ' . WINDOW )
        : respond( '429 Too Many Requests', 'text/html; charset=utf-8', page($message),   'Retry-After: ' . WINDOW );
}

=head2 page

    my $html = page($message);

=cut

sub page {
    my ($message) = @_;
    return qq{<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex">}
        . qq{<title>Discovery search</title></head><body><p>$message</p></body></html>\n};
}

=head2 respond

    respond( $status, $content_type, $body, @headers );

Prints a CGI response and ends the process, so the script and Koha never load.

=cut

sub respond {
    my ( $status, $content_type, $body, @headers ) = @_;
    binmode STDOUT;
    print join(
        "\r\n",
        "Status: $status",       @headers, "Content-Type: $content_type", 'Cache-Control: no-store',
        'X-Robots-Tag: noindex', q{},      q{}
        ),
        $body;
    exit 0;
}
