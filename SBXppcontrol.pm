#####################################################################
#
# Description:      Password policy control module
#
# Author:           Raymond Edah <ray@skyblue.pty.st>
# Current Revision: $Revision: 1.19 $
# Branch:           $Name:  $
# Last Update:      $Author: raymonde $ on $Date: 2007/04/04 08:25:24 $
#
#####################################################################
#
# Change History
# Please do NOT use tabs in this section.
#
#####################################################################
#
# 2007-11-20  RBE - File created
#
#####################################################################
package SBXppcontrol;
#####################################################################
use strict;
use Convert::ASN1;
use Net::LDAP::Control;
#####################################################################
our $VERSION = "0.1a";
our @ISA = qw(Net::LDAP::Control);
#####################################################################

#####################################################################
# Description: Object Constructor.
#####################################################################
sub new
{
   my $self = {};
   my $class = shift;
   my ($server_ppc) = @_;
   
   $self->{pprExpireTime}                  = undef;
   $self->{pprGraceLoginsLeft}             = undef;
   $self->{pprError}                       = undef;
   $self->{pprIncludesTimeWarning}         = 0;
   $self->{pprIncludesGraceBindsWarning}   = 0;
   $self->{pprIncludesError}               = 0;
   $self->{ppc}                            = undef;
   $self->{myControlType}                  = '1.3.6.1.4.1.42.2.27.8.5.1';
   $self->{asnError}                       = undef;
   $self->{ASN}                            = Convert::ASN1->new();
   $self->{asnStructure}                   = undef;
   
   if ($server_ppc->{type} eq $self->{myControlType})
   {
      $self->{ASN}->prepare(q<
      PasswordPolicyWarning ::= CHOICE {
         timeBeforeExpiration [0] INTEGER,
         graceAuthNsRemaining [1] INTEGER
      }
      PasswordPolicyError ::= ENUMERATED {
         passwordExpired             (0),
         accountLocked               (1),
         changeAfterReset            (2),
         passwordModNotAllowed       (3),
         mustSupplyOldPassword       (4),
         insufficientPasswordQuality (5),
         passwordTooShort            (6),
         passwordTooYoung            (7),
         passwordInHistory           (8)
      }
      PasswordPolicyResponseValue ::= SEQUENCE {
         warning [0] PasswordPolicyWarning OPTIONAL,
         error   [1] PasswordPolicyError OPTIONAL
      }
      >) or $self->{asnError} = $self->{ASN}->error;
      
      $self->{asnStructure} = $self->{ASN}->find('PasswordPolicyResponseValue');
      $self->{ppc} = $self->{asnStructure}->decode($server_ppc->{value});
      
      if (exists($self->{ppc}->{error}))
      {
         $self->{pprIncludesError} = 1;
         $self->{pprError} = $self->{ppc}->{error};
      }
      elsif (exists($self->{ppc}->{warning}))
      {
         if (exists($self->{ppc}->{warning}->{timeBeforeExpiration}))
         {
            $self->{pprIncludesTimeWarning} = 1;
            $self->{pprExpireTime} = $self->{ppc}->{warning}->{timeBeforeExpiration};
         }
         elsif(exists($self->{ppc}->{warning}->{graceAuthNsRemaining}))
         {
            $self->{pprIncludesGraceBindsWarning} = 1;
            $self->{pprGraceLoginsLeft} = $self->{ppc}->{warning}->{graceAuthNsRemaining};
         }
      }
   }
   bless ($self, $class);
   return $self;
}

#####################################################################
# Description: Returns the error code in the response control. If
#              the server response did not contain an error, undef
#              is returned.
#####################################################################
sub getErrorCode
{
   my $self = shift;
   return $self->{pprError};
}

#####################################################################
# Description: Returns value for timeBeforeExpiration in seconds.
#              the server response did not include timeBeforeExpiration,
#              undef is returned.
#####################################################################
sub getTimeBeforeExpiration
{
   my $self = shift;
   return $self->{pprExpireTime};
}

#####################################################################
# Description: Returns value for graceAuthNsRemaining (Number of grace
#              logins left).If the server response did not include
#              graceAuthNsRemaining, undef is returned.
#####################################################################
sub getGraceAuthNsRemaining
{
   my $self = shift;
   return $self->{pprGraceLoginsLeft};
}

#####################################################################
# Description: Returns boolean TRUE is the response control from the
#              server included a warning with timeBeforeExpiration.
#              Boolean FALSE is returned otherwise.
#####################################################################
sub ppResponseHasTimeWarning
{
   my $self = shift;
   return $self->{pprIncludesTimeWarning};
}

#####################################################################
# Description: Returns boolean TRUE is the response control from the
#              server included a warning with gcareAuthNsRemaining.
#              Boolean FALSE is returned otherwise.
#####################################################################
sub ppResponseHasGraceWarning
{
   my $self = shift;
   return $self->{pprIncludesGraceBindsWarning};
}

#####################################################################
# Description: Returns boolean TRUE is the response control from the
#              server included an error code.
#              Boolean FALSE is returned otherwise.
#####################################################################
sub ppResponseHasError
{
   my $self = shift;
   return $self->{pprIncludesError};
}

#####################################################################
# Description: Returns a string interpretation of the error code in
#              the response control from the server. If the error code
#              is not recognised or the server response did not include
#              an error code, the string "Unknown error code" is
#              returned.
#####################################################################
sub ppErrorText
{
   my $self = shift;
   if ($self->{pprError} == 0) { return "Password expired " }
   elsif ($self->{pprError} == 1) { return "Account locked" }
   elsif ($self->{pprError} == 2) { return "Password must be changed" }
   elsif ($self->{pprError} == 3) { return "Policy prevents password modification" }
   elsif ($self->{pprError} == 4) { return "Policy requires old password in order to change password" }
   elsif ($self->{pprError} == 5) { return "Password fails quality checks" }
   elsif ($self->{pprError} == 6) { return "Password is too short for policy" }
   elsif ($self->{pprError} == 7) { return "Password has been changed to recently" }
   elsif ($self->{pprError} == 8) { return "New password is in list of old passwords" }
   else {}
   return "Unknown error code";
}

1;
