#include "orbsvcs/Security/Caller.h"

#include "tao/ORB_Constants.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  /// UTF-8 to a wide string, one wchar_t per code point; a malformed
  /// byte becomes U+FFFD.
  CORBA::WChar *
  widen (std::string const &s)
  {
    std::wstring out;
    for (size_t i = 0; i < s.size (); )
      {
        unsigned char const c = static_cast<unsigned char> (s[i]);
        unsigned long cp = 0xFFFD;
        size_t n = 1;
        if (c < 0x80)
          cp = c;
        else if ((c >> 5) == 0x6 && i + 1 < s.size ())
          {
            cp = ((c & 0x1Fu) << 6) | (static_cast<unsigned char> (s[i + 1]) & 0x3Fu);
            n = 2;
          }
        else if ((c >> 4) == 0xE && i + 2 < s.size ())
          {
            cp = ((c & 0x0Fu) << 12) | ((static_cast<unsigned char> (s[i + 1]) & 0x3Fu) << 6)
                 | (static_cast<unsigned char> (s[i + 2]) & 0x3Fu);
            n = 3;
          }
        else if ((c >> 3) == 0x1E && i + 3 < s.size () && sizeof (wchar_t) >= 4)
          {
            cp = ((c & 0x07u) << 18) | ((static_cast<unsigned char> (s[i + 1]) & 0x3Fu) << 12)
                 | ((static_cast<unsigned char> (s[i + 2]) & 0x3Fu) << 6)
                 | (static_cast<unsigned char> (s[i + 3]) & 0x3Fu);
            n = 4;
          }
        out += static_cast<wchar_t> (cp);
        i += n;
      }
    return CORBA::wstring_dup (out.c_str ());
  }

  SecurityLevel3::PrincipalName
  name_of (std::string const &principal)
  {
    SecurityLevel3::PrincipalName n;
    if (principal.compare (0, 9, "spiffe://") == 0)
      n.the_type = TAO::Security::NT_SPIFFE_ID;
    else if (principal == "anonymous")
      n.the_type = SecurityLevel3::NT_Anonymous;
    else if (principal.find ('=') != std::string::npos)
      n.the_type = SecurityLevel3::NT_X509DirectoryNamePath;
    else
      n.the_type = SecurityLevel3::NT_StringName;
    n.the_name.length (1);
    n.the_name[0] = widen (principal);
    return n;
  }

  ::Security::SecAttribute
  attribute (unsigned short family, ::Security::SecurityAttributeType type, std::string const &value)
  {
    ::Security::SecAttribute a;
    a.attribute_type.attribute_family.family_definer = 0;   // OMG
    a.attribute_type.attribute_family.family = family;
    a.attribute_type.attribute_type = type;
    a.value.length (static_cast<CORBA::ULong> (value.size ()));
    for (CORBA::ULong i = 0; i < a.value.length (); ++i)
      a.value[i] = static_cast<CORBA::Octet> (value[i]);
    return a;
  }
}

std::string
TAO::Security::Caller::transport () const
{
  return this->spiffe_ids.empty () ? this->subject : this->spiffe_ids.front ();
}

std::string
TAO::Security::Caller::effective () const
{
  if (!this->asserted.empty ())
    return this->asserted;
  if (!this->authenticated.empty ())
    return this->authenticated;
  std::string const t = this->transport ();
  if (!t.empty ())
    return t;
  return this->local ? "local" : "anonymous";
}

std::string const &
TAO::Security::Caller::effective_mech () const
{
  return this->asserted.empty () ? this->authenticated_mech : this->asserted_mech;
}

std::vector<std::string>
TAO::Security::Caller::principals () const
{
  std::vector<std::string> out;
  auto add = [&out] (std::string const &p) {
    if (p.empty ())
      return;
    for (auto const &have : out)
      if (have == p)
        return;
    out.push_back (p);
  };
  add (this->effective ());
  add (this->asserted);
  add (this->asserter);
  add (this->authenticated);
  for (auto const &id : this->spiffe_ids)
    add (id);
  add (this->subject);
  return out;
}

TAO::Security::Caller_Policy::~Caller_Policy () = default;

TAO::Security::Caller_Credentials::Caller_Credentials (Caller const &caller, char const *mechanism)
  : caller_ (caller),
    mechanism_ (mechanism == nullptr ? "" : mechanism)
{
}

TAO::Security::Caller_Credentials::~Caller_Credentials () = default;

TAO::Security::Caller const &
TAO::Security::Caller_Credentials::caller () const
{
  return this->caller_;
}

TAO::Security::Caller const *
TAO::Security::Caller_Credentials::caller_of (SecurityLevel2::Credentials_ptr creds)
{
  Caller_Credentials const *const c = dynamic_cast<Caller_Credentials const *> (creds);
  return c == nullptr ? nullptr : &c->caller_;
}

SecurityLevel2::Credentials_ptr
TAO::Security::Caller_Credentials::copy ()
{
  SecurityLevel2::Credentials_ptr c = SecurityLevel2::Credentials::_nil ();
  ACE_NEW_THROW_EX (c, Caller_Credentials (this->caller_, this->mechanism_.c_str ()), CORBA::NO_MEMORY ());
  return c;
}

void
TAO::Security::Caller_Credentials::destroy ()
{
}

::Security::InvocationCredentialsType
TAO::Security::Caller_Credentials::credentials_type ()
{
  return ::Security::SecReceivedCredentials;
}

::Security::AuthenticationStatus
TAO::Security::Caller_Credentials::authentication_state ()
{
  return this->caller_.effective () == "anonymous" ? ::Security::SecAuthFailure : ::Security::SecAuthSuccess;
}

char *
TAO::Security::Caller_Credentials::mechanism ()
{
  return CORBA::string_dup (this->mechanism_.c_str ());
}

::Security::AssociationOptions
TAO::Security::Caller_Credentials::accepting_options_supported ()
{
  throw CORBA::NO_IMPLEMENT ();
}

void
TAO::Security::Caller_Credentials::accepting_options_supported (::Security::AssociationOptions)
{
  throw CORBA::BAD_OPERATION ();
}

::Security::AssociationOptions
TAO::Security::Caller_Credentials::accepting_options_required ()
{
  throw CORBA::NO_IMPLEMENT ();
}

void
TAO::Security::Caller_Credentials::accepting_options_required (::Security::AssociationOptions)
{
  throw CORBA::BAD_OPERATION ();
}

::Security::AssociationOptions
TAO::Security::Caller_Credentials::invocation_options_supported ()
{
  throw CORBA::NO_IMPLEMENT ();
}

void
TAO::Security::Caller_Credentials::invocation_options_supported (::Security::AssociationOptions)
{
  throw CORBA::BAD_OPERATION ();
}

::Security::AssociationOptions
TAO::Security::Caller_Credentials::invocation_options_required ()
{
  throw CORBA::NO_IMPLEMENT ();
}

void
TAO::Security::Caller_Credentials::invocation_options_required (::Security::AssociationOptions)
{
  throw CORBA::BAD_OPERATION ();
}

::CORBA::Boolean
TAO::Security::Caller_Credentials::get_security_feature (::Security::CommunicationDirection,
                                                         ::Security::SecurityFeature)
{
  throw CORBA::NO_IMPLEMENT ();
}

::CORBA::Boolean
TAO::Security::Caller_Credentials::set_attributes (::Security::AttributeList const &,
                                                   ::Security::AttributeList_out actual)
{
  // Received credentials are what the caller proved; they are not changed.
  actual = new ::Security::AttributeList;
  return false;
}

::Security::AttributeList *
TAO::Security::Caller_Credentials::get_attributes (::Security::AttributeTypeList const &attributes)
{
  std::string const who = this->caller_.effective ();
  ::Security::AttributeList all;
  all.length (2);
  all[0] = attribute (1, ::Security::AccessId, who);
  all[1] = attribute (0, ::Security::AuditId, who);

  ::Security::AttributeList *out = nullptr;
  ACE_NEW_THROW_EX (out, ::Security::AttributeList, CORBA::NO_MEMORY ());
  for (CORBA::ULong i = 0; i < all.length (); ++i)
    {
      bool wanted = attributes.length () == 0;
      for (CORBA::ULong j = 0; !wanted && j < attributes.length (); ++j)
        wanted = attributes[j].attribute_family.family == all[i].attribute_type.attribute_family.family
                 && attributes[j].attribute_type == all[i].attribute_type.attribute_type;
      if (wanted)
        {
          CORBA::ULong const n = out->length ();
          out->length (n + 1);
          (*out)[n] = all[i];
        }
    }
  return out;
}

::CORBA::Boolean
TAO::Security::Caller_Credentials::is_valid (::Security::UtcT_out)
{
  // Valid for the request it was built for.
  return true;
}

::CORBA::Boolean
TAO::Security::Caller_Credentials::refresh (::CORBA::Any const &)
{
  return false;
}

SecurityLevel2::Credentials_ptr
TAO::Security::Caller_Credentials::accepting_credentials ()
{
  throw CORBA::NO_IMPLEMENT ();
}

::Security::AssociationOptions
TAO::Security::Caller_Credentials::association_options_used ()
{
  throw CORBA::NO_IMPLEMENT ();
}

::Security::DelegationState
TAO::Security::Caller_Credentials::delegation_state ()
{
  return ::Security::SecInitiator;
}

::Security::DelegationMode
TAO::Security::Caller_Credentials::delegation_mode ()
{
  return ::Security::SecDelModeNoDelegation;
}

SecurityLevel3::Principal *
TAO::Security::principal_of (Caller const &caller)
{
  // A Kerberos principal (K5) has the SecurityLevel3 Kerberos name type.
  auto typed = [&caller] (std::string const &n) {
    SecurityLevel3::PrincipalName pn = name_of (n);
    if ((n == caller.asserted && caller.asserted_mech == "krb5")
        || (n == caller.authenticated && caller.authenticated_mech == "krb5"))
      pn.the_type = SecurityLevel3::NT_KerberosName;
    return pn;
  };
  std::vector<std::string> const names = caller.principals ();
  SecurityLevel3::PrincipalNameList alternates;
  alternates.length (names.empty () ? 0 : static_cast<CORBA::ULong> (names.size () - 1));
  for (size_t i = 1; i < names.size (); ++i)
    alternates[static_cast<CORBA::ULong> (i - 1)] = typed (names[i]);

  // Ticket groups (K4) as privileges issued by the Kerberos realm, only
  // for the principal whose ticket carried them: never for an asserted
  // caller, whose groups the asserter's ticket does not speak for.
  SecurityLevel3::ScopedPrivilegesList privileges;
  if (!caller.groups.empty () && caller.asserted.empty () && !caller.authenticated.empty ())
    {
      privileges.length (1);
      SecurityLevel3::ScopedPrivileges &sp = privileges[0];
      sp.privilege_authority.the_type = TAO::Security::NT_KERBEROS_REALM;
      sp.privilege_authority.the_name.length (1);
      sp.privilege_authority.the_name[0] = widen (caller.groups_authority);
      sp.privileges.length (static_cast<CORBA::ULong> (caller.groups.size ()));
      for (CORBA::ULong i = 0; i < sp.privileges.length (); ++i)
        {
          sp.privileges[i].the_type = TAO::Security::PA_GROUP_SID;
          sp.privileges[i].the_value = widen (caller.groups[i]);
        }
    }

  OBV_SecurityLevel3::SimplePrincipal *p = nullptr;
  ACE_NEW_THROW_EX (p,
                    OBV_SecurityLevel3::SimplePrincipal (SecurityLevel3::PT_Simple,
                                                         typed (caller.effective ()),
                                                         SecurityLevel3::PrinAttributeList (),
                                                         privileges,
                                                         caller.effective () != "anonymous",
                                                         alternates),
                    CORBA::NO_MEMORY ());
  return p;
}

TAO_END_VERSIONED_NAMESPACE_DECL
