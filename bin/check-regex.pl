#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Test a regex to see if it is vulnerable
#
# Dependencies:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use JSON::PP;

# Globals.
my $PATTERN_SAFE       = "SAFE";
my $PATTERN_VULNERABLE = "VULNERABLE";
my $PATTERN_UNKNOWN    = "UNKNOWN";
my $PATTERN_INVALID    = "INVALID";

my $REQUEST_LOOKUP = "LOOKUP";
my $REQUEST_UPDATE = "UPDATE";

my $DEBUG = 0;
if ($ENV{REGEX_DEBUG}) {
  $DEBUG = 1;
}

my $tmpFile = "/tmp/check-regex-$$.json";
my $progressFile = "/tmp/check-regex-$$-progress.log";
unlink($tmpFile, $progressFile);

# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $detectVuln = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect/detect-vuln.pl";
my $validateVuln = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/validate/validate-vuln.pl";

for my $script ($detectVuln, $validateVuln) {
  if (not -x $script) {
    die "Error, could not find script $script\n";
  }
}

sub check_vulnerability {
  my $query = {"pattern" => $_[0]};

  my $result;

  $result = { "pattern" => $query->{pattern} };

  my %defaults = ("detectVuln_timeLimit"   => 60*1,   # 1 minute in seconds
                  "detectVuln_memoryLimit" => 1024*8, # 8GB in MB. Weideman/java is greedy.
                  # $validateVuln requires nPumps and timeLimit.
                  # Choose sensible defaults.
                  "validateVuln_language" => "java",
                  "validateVuln_nPumps"    => 250000, # 250K pumps
                  "validateVuln_timeLimit" => 5,      # 5 seconds
                  );
  for my $key (keys %defaults) {
    &log("Using default for $key: $defaults{$key}");
    $query->{$key} = $defaults{$key};
  }

  ### Query detectors.

  # Prep a query to $detectVuln.
  my $detectVulnQuery = { "pattern" => $query->{pattern} };

  # Let $detectVuln set these defaults itself.
  if (defined $query->{detectVuln_detectors}) {
    $detectVulnQuery->{detectors} = $query->{detectVuln_detectors};
  }
  if (defined $query->{detectVuln_timeLimit}) {
    $detectVulnQuery->{timeLimit} = $query->{detectVuln_timeLimit};
  }
  if (defined $query->{detectVuln_memoryLimit}) {
    $detectVulnQuery->{memoryLimit} = $query->{detectVuln_memoryLimit};
  }

  # Query $detectVuln.
  &log("Querying detectors");
  &writeToFile("file"=>$tmpFile, "contents"=>encode_json($detectVulnQuery));
  my $detectReport = decode_json(&chkcmd("$detectVuln $tmpFile 2>>$progressFile"));
  &log("Detectors said: " . encode_json($detectReport));

  $result->{detectReport} = $detectReport;

  ### Validate any reported vulnerabilities.

  # Prep a query to $validateVuln.
  my $validateVulnQuery = { "pattern"   => $query->{pattern},
                            "language"  => $query->{validateVuln_language},
                            "nPumps"    => $query->{validateVuln_nPumps},
                            "timeLimit" => $query->{validateVuln_timeLimit},
                          };

  # See what each detector thought.
  # Bail if any finds a vulnerability so we don't waste time.
  $result->{isVulnerable} = 0;
  for my $do (@{$detectReport->{detectorOpinions}}) {
    # Are we done?
    last if ($result->{isVulnerable});

    # Check this detector's opinion.
    &log("Checking $do->{name} for timeout-triggering evil input");

    # Maybe vulnerable?
    if ($do->{hasOpinion} and $do->{opinion}->{canAnalyze} and not $do->{opinion}->{isSafe}) {
      my $isVariant = ($do->{patternVariant} eq $query->{pattern}) ? 1 : 0;
      &log("$do->{name}: the regex may be vulnerable (isVariant $isVariant)");
      # If unparseable, evilInput is an empty array or has elt 0 'COULD-NOT-PARSE'
      for my $evilInput (@{$do->{opinion}->{evilInput}}) {
        if ($evilInput eq "COULD-NOT-PARSE") {
          &log("  $do->{name}: Could not parse the evil input");
          next;
        }

        # Does this evilInput trigger catastrophic backtracking?
        $validateVulnQuery->{evilInput} = $evilInput;
        my $queryString = encode_json($validateVulnQuery);
        &log("  $do->{name}: Validating the evil input (query: $queryString)");
        &writeToFile("file"=>$tmpFile, "contents"=>$queryString);
        my $report = decode_json(&chkcmd("$validateVuln $tmpFile 2>>$progressFile"));
        if ($report->{timedOut}) {
          &log("  $do->{name}: evil input triggered a regex timeout");
          $result->{isVulnerable} = 1;
          $result->{validateReport} = $report;
          last;
        } else {
          &log("  $do->{name}: evil input did not trigger a regex timeout");
        }
      }
    } else {
      &log("  $do->{name}: says not vulnerable");
    }
  }

  unlink($tmpFile, $progressFile) unless $DEBUG;

  # Report results.
  print $result;
  return encode_json($result);
}

##############################

# input: %args: keys: file
# output: $contents
sub readFile {
  my %args = @_;

	open(my $FH, '<', $args{file}) or die "Error, could not read $args{file}: $!\n";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}

# input: %args: keys: file contents
# output: $file
sub writeToFile {
  my %args = @_;

	open(my $fh, '>', $args{file});
	print $fh $args{contents};
	close $fh;

  return $args{file};
}

sub cmd {
  my ($cmd) = @_;
  &log("$cmd");
  my $out = `$cmd`;
  my $rc = $? >> 8;

  return ($rc, $out);
}

sub chkcmd {
  my ($cmd) = @_;
  my ($rc, $out) = &cmd($cmd);
  if ($rc) {
    die "Error, cmd <$cmd> gave rc $rc:\n$out\n";
  }

  return $out;
}

sub log {
  my ($msg) = @_;
  print STDERR "$msg\n";
}

1;