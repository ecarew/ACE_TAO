#include "orbsvcs/Log_Macros.h"
#include "orbsvcs/Security/SL2_Audit.h"
#include "orbsvcs/Security/Audit_Logger.h"

#include "tao/AnyTypeCode/Any.h"

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace
{
  char const *
  event_name (::Security::AuditEventType const &type)
  {
    // Only the OMG family (definer 0, family 7, "audit") has the
    // standard meanings.
    if (type.event_family.family_definer == 0)
      switch (type.event_type)
        {
        case ::Security::AuditPrincipalAuth: return "authn";
        case ::Security::AuditSessionAuth: return "session";
        case ::Security::AuditAuthorization: return "authz";
        case ::Security::AuditInvocation: return "invoke";
        case ::Security::AuditSecEnvChange: return "secenv";
        case ::Security::AuditPolicyChange: return "policy";
        case ::Security::AuditObjectCreation: return "create";
        case ::Security::AuditObjectDestruction: return "destroy";
        case ::Security::AuditNonRepudiation: return "nonrepudiation";
        default: break;
        }
    return "other";
  }

  // ACE_Time_Value for a TimeBase::UtcT (100 ns units since 1582-10-15).
  ACE_Time_Value
  from_utc (::Security::UtcT const &utc)
  {
    constexpr TimeBase::TimeT const epoch_offset = ACE_UINT64_LITERAL (0x1B21DD213814000);
    if (utc.time <= epoch_offset)
      return ACE_Time_Value::zero;
    TimeBase::TimeT const since_1970 = utc.time - epoch_offset;
    return ACE_Time_Value (static_cast<time_t> (since_1970 / 10000000U),
                           static_cast<suseconds_t> ((since_1970 % 10000000U) / 10U));
  }
}

namespace TAO
{
  namespace Security
  {
    AuditChannel::AuditChannel (Audit_Logger *logger)
      : logger_ (logger ? logger : Audit_Logger::instance ())
    {
    }

    AuditChannel::~AuditChannel ()
    = default;

    void
    AuditChannel::audit_write (const ::Security::AuditEventType &event_type,
                               const SecurityLevel2::CredentialsList & /*creds*/,
                               const ::Security::UtcT &time,
                               const ::Security::SelectorValueList &descriptors,
                               const ::CORBA::Any &event_specific_data)
    {
      std::string event = event_name (event_type);
      ::CORBA::Boolean success = true;
      char const *reason = nullptr;
      Audit_Record::Fields fields;

      for (::CORBA::ULong i = 0; i < descriptors.length (); ++i)
        {
          ::Security::SelectorValue const &sv = descriptors[i];
          if (sv.selector == ::Security::SuccessFailure)
            {
              ::CORBA::Boolean b = true;
              if (sv.value >>= ::CORBA::Any::to_boolean (b))
                success = b;
              continue;
            }

          char const *s = nullptr;
          if (!(sv.value >>= s) || s == nullptr)
            continue;

          switch (sv.selector)
            {
            case ::Security::InterfaceName: fields.emplace_back ("iface", s); break;
            case ::Security::Operation: fields.emplace_back ("op", s); break;
            case Audit_Selector::Reason: reason = s; break;
            case Audit_Selector::Source: fields.emplace_back ("src", s); break;
            case Audit_Selector::Peer: fields.emplace_back ("peer", s); break;
            case Audit_Selector::Actor: fields.emplace_back ("act", s); break;
            case Audit_Selector::CertSerial: fields.emplace_back ("cert_serial", s); break;
            case Audit_Selector::TokenId: fields.emplace_back ("jti", s); break;
            case Audit_Selector::Target: fields.emplace_back ("target", s); break;
            case Audit_Selector::Event: event = s; break;
            default: break;
            }
        }

      Audit_Record record (event.c_str (), success, reason);
      for (auto const &f : fields)
        record.field (f.first.c_str (), f.second);
      char const *text = nullptr;
      if (event_specific_data >>= text)
        record.text (text);
      record.time = from_utc (time);

      this->logger_->write (record);
    }

    ::Security::AuditChannelId
    AuditChannel::audit_channel_id ()
    {
      return 1;
    }

    AuditDecision::AuditDecision (SecurityLevel2::AuditChannel_ptr channel)
      : channel_ (SecurityLevel2::AuditChannel::_duplicate (channel))
    {
    }

    AuditDecision::~AuditDecision ()
    = default;

    ::CORBA::Boolean
    AuditDecision::audit_needed (const ::Security::AuditEventType & /*event_type*/,
                                 const ::Security::SelectorValueList & /*value_list*/)
    {
      return true;
    }

    SecurityLevel2::AuditChannel_ptr
    AuditDecision::audit_channel ()
    {
      return SecurityLevel2::AuditChannel::_duplicate (this->channel_.in ());
    }
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL
