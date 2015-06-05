require "akami/wsse/certs"

module Akami
  class WSSE
    class Signature
      include Akami::XPathHelper
      include Akami::C14nHelper

      class MissingCertificate < RuntimeError; end

      # For a +Savon::WSSE::Certs+ object. To hold the certs we need to sign.
      attr_accessor :certs

      # Without a document, the document cannot be signed.
      # Generate the document once, and then set document and recall #to_token
      def document
        return nil if @document.nil?
        @document.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)
      end

      def document=(document)
        @document = Nokogiri::XML(document)
      end

      DIGESTERS = {
        # SHA1
        sha1: {
          algorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
          algorithm2: 'http://www.w3.org/2000/09/xmldsig#sha1',
          digester: lambda { OpenSSL::Digest::SHA1.new }
        },
        # SHA 256
        sha256: {
          algorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
          algorithm2: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
          digester: lambda { OpenSSL::Digest::SHA256.new }
        },
        # GOST R 34-11 94
        gost3411: {
          algorithm: 'http://www.w3.org/2001/04/xmldsig-more#gostr3411',
          algorithm2: 'http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411',
          digester: lambda {
            engine = OpenSSL::Engine.by_id('gost')
            engine.set_default(0xFFFF)
            engine.digest('md_gost94')
          }
        }
      }

      ExclusiveXMLCanonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#'.freeze

      X509v3ValueType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'.freeze
      Base64EncodingType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'.freeze

      SignatureNamespace = 'http://www.w3.org/2000/09/xmldsig#'.freeze

      def initialize(certs = Certs.new, digest_algorithm = :sha256)
        @certs = certs
        @digest_info = DIGESTERS[digest_algorithm].clone
        @digest_info[:digester] = @digest_info[:digester].call
      end

      def have_document?
        !!document
      end

      # Cache "now" so that digests match...
      # TODO: figure out how we might want to expire this cache...
      def now
        @now ||= Time.now
      end

      def body_id
        @body_id ||= "Body-#{uid}".freeze
      end

      def security_token_id
        @security_token_id ||= "SecurityToken-#{uid}".freeze
      end

      def body_attributes
        {
          "xmlns:wsu" => Akami::WSSE::WSU_NAMESPACE,
          "wsu:Id" => body_id,
        }
      end

      def to_token
        return {} unless have_document?

        sig = signed_info.merge(key_info).merge(signature_value)
        sig.merge! :order! => []
        [ "ds:SignedInfo", "ds:SignatureValue", "ds:KeyInfo" ].each do |key|
          sig[:order!] << key if sig[key]
        end

        token = {
          "ds:Signature" => sig,
          :attributes! => { "ds:Signature" => { "xmlns:ds" => SignatureNamespace } },
        }

        # token.deep_merge!(binary_security_token) if certs.cert
        token.merge! :order! => []
        [ "wsse:BinarySecurityToken", "ds:Signature" ].each do |key|
          token[:order!] << key if token[key]
        end

        token[:order!] << 'wsse:UsernameToken'

        token
      end

      private

      def binary_security_token
        {
          "wsse:BinarySecurityToken" => Base64.encode64(certs.cert.to_der).gsub("\n", ''),
          :attributes! => { "wsse:BinarySecurityToken" => {
            "wsu:Id" => security_token_id,
            'EncodingType' => Base64EncodingType,
            'ValueType' => X509v3ValueType,
            "xmlns:wsu" => Akami::WSSE::WSU_NAMESPACE,
          } }
        }
      end

      def key_info
        {
          "ds:KeyInfo" => {
            "wsse:SecurityTokenReference" => {
              "ds:X509Data" => {
                "ds:X509IssuerSerial" => {
                  "ds:X509IssuerName" => certs.cert.issuer.to_s.gsub(/^\//, '').gsub(/\//, ','),
                  "ds:X509SerialNumber" => certs.cert.serial.to_s
                }
              }
            }
          }
        }
      end

      def signature_value
        { "ds:SignatureValue" => the_signature }
      rescue MissingCertificate
        {}
      end

      def signed_info
        {
          "ds:SignedInfo" => {
            "ds:CanonicalizationMethod" => {
              "ec:InclusiveNamespaces/" => nil,
              :attributes! => {
                "ec:InclusiveNamespaces/" => { "xmlns:ec" => "http://www.w3.org/2001/10/xml-exc-c14n#", "PrefixList" => "soap"}
              }
            },
            "ds:SignatureMethod/" => nil,
            "ds:Reference" => [
              signed_info_transforms.merge(signed_info_digest_method).merge({ "DigestValue" => body_digest }),
            ],
            :attributes! => {
              "ds:CanonicalizationMethod/" => { "Algorithm" => ExclusiveXMLCanonicalizationAlgorithm },
              "ds:SignatureMethod/" => { "Algorithm" => @digest_info[:algorithm2] },
              "ds:Reference" => { "URI" => ["##{body_id}"] },
            },
            :order! => [ "ds:CanonicalizationMethod", "ds:SignatureMethod/", "ds:Reference" ],
          },
        }
      end

      def the_signature
        raise MissingCertificate, "Expected a private_key for signing" unless certs.private_key
        signed_info = at_xpath(@document, "//Envelope/Header/Security/Signature/SignedInfo")
        signed_info = signed_info ? canonicalize(signed_info) : ""
        signature = certs.private_key.sign(@digest_info[:digester], signed_info)
        Base64.encode64(signature).gsub("\n", '') # TODO: DRY calls to Base64.encode64(...).gsub("\n", '')
      end

      def body_digest
        body = canonicalize(at_xpath(@document, "//Envelope/Body"))
        Base64.encode64(@digest_info[:digester].digest(body)).strip
      end

      def signed_info_digest_method
        {
          "DigestMethod/" => nil,
          :attributes! => { "DigestMethod/" => { "Algorithm" => @digest_info[:algorithm] } }
        }
      end

      def signed_info_transforms
        {
          "ds:Transforms" => {
            "ds:Transform" => {
              "ec:InclusiveNamespaces/" => nil,
              :attributes! => {
                "ec:InclusiveNamespaces/" => { "xmlns:ec" => "http://www.w3.org/2001/10/xml-exc-c14n#", "PrefixList" =>"" }
              }
            },
            :attributes! => { "ds:Transform" => { "Algorithm" => ExclusiveXMLCanonicalizationAlgorithm } }
          }
        }
      end

      def uid
        OpenSSL::Digest::SHA1.hexdigest([Time.now, rand].collect(&:to_s).join('/'))
      end
    end
  end
end
