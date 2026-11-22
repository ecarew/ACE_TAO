// -*- C++ -*-

//=============================================================================
/**
 * @file SL2_Audit.h
 *
 * SecurityLevel2 AuditDecision and AuditChannel backed by the
 * TAO::Security::Audit_Logger.
 */
//=============================================================================

#ifndef TAO_SL2_AUDIT_H
#define TAO_SL2_AUDIT_H

#include /**/ "ace/pre.h"
#include "orbsvcs/Security/security_export.h"

#if !defined (ACE_LACKS_PRAGMA_ONCE)
# pragma once
#endif /* ACE_LACKS_PRAGMA_ONCE */

#include "orbsvcs/SecurityLevel2C.h"
#include "tao/LocalObject.h"

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4250)
#endif /* _MSC_VER */

TAO_BEGIN_VERSIONED_NAMESPACE_DECL

namespace TAO
{
  namespace Security
  {
    class Audit_Logger;

    /**
     * TAO selector types for AuditChannel::audit_write() descriptors,
     * beyond the standard InterfaceName .. DayOfWeek.  Each value is a
     * string in the Any and becomes the audit record field named in the
     * comment.
     */
    namespace Audit_Selector
    {
      constexpr ::Security::SelectorType Base = 0x54410000U;  // 'T' 'A'
      constexpr ::Security::SelectorType Reason = Base + 1;      ///< reason
      constexpr ::Security::SelectorType Source = Base + 2;      ///< src (host:port)
      constexpr ::Security::SelectorType Peer = Base + 3;        ///< peer identity
      constexpr ::Security::SelectorType Actor = Base + 4;       ///< act (delegation)
      constexpr ::Security::SelectorType CertSerial = Base + 5;  ///< cert_serial
      constexpr ::Security::SelectorType TokenId = Base + 6;     ///< jti
      constexpr ::Security::SelectorType Target = Base + 7;      ///< target
      constexpr ::Security::SelectorType Event = Base + 8;       ///< event name override
    }

    /**
     * @class AuditChannel
     *
     * @brief Writes SecurityLevel2 audit events as audit records.
     *
     * The event type gives the event field (AuditPrincipalAuth "authn",
     * AuditSessionAuth "session", AuditAuthorization "authz",
     * AuditInvocation "invoke", ...).  Descriptors give the rest:
     * SuccessFailure (boolean, default true) the result, Operation and
     * InterfaceName the op and iface fields, and the Audit_Selector types
     * the TAO fields.  A string in @c event_specific_data becomes the
     * record's free text.  Credentials and object references are not
     * logged.
     */
    class TAO_Security_Export AuditChannel
      : public virtual SecurityLevel2::AuditChannel,
        public virtual ::CORBA::LocalObject
    {
    public:
      /// Writes to @a logger, or to Audit_Logger::instance() if null.
      explicit AuditChannel (Audit_Logger *logger = nullptr);

      void audit_write (const ::Security::AuditEventType &event_type,
                        const SecurityLevel2::CredentialsList &creds,
                        const ::Security::UtcT &time,
                        const ::Security::SelectorValueList &descriptors,
                        const ::CORBA::Any &event_specific_data) override;

      ::Security::AuditChannelId audit_channel_id () override;

    protected:
      ~AuditChannel () override;

    private:
      Audit_Logger *logger_;
    };

    /**
     * @class AuditDecision
     *
     * @brief Every event is audited: the design logs every security
     * decision, and volume is controlled by rate limiting instead.
     */
    class TAO_Security_Export AuditDecision
      : public virtual SecurityLevel2::AuditDecision,
        public virtual ::CORBA::LocalObject
    {
    public:
      explicit AuditDecision (SecurityLevel2::AuditChannel_ptr channel);

      ::CORBA::Boolean audit_needed (const ::Security::AuditEventType &event_type,
                                     const ::Security::SelectorValueList &value_list) override;

      SecurityLevel2::AuditChannel_ptr audit_channel () override;

    protected:
      ~AuditDecision () override;

    private:
      SecurityLevel2::AuditChannel_var channel_;
    };
  }
}

TAO_END_VERSIONED_NAMESPACE_DECL

#if defined(_MSC_VER)
#pragma warning(pop)
#endif /* _MSC_VER */

#include /**/ "ace/post.h"

#endif /* TAO_SL2_AUDIT_H */
