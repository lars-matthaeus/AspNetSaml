using Saml;
using System.IO.Compression;
using System.IO;
using System.Text;
using Shouldly;
using System.Security.Claims;
using System.Runtime.ConstrainedExecution;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AspNetSaml.Tests
{
	[TestClass]
	public class UnitTests
	{
		//cert and signature taken form here: www.samltool.com/generic_sso_res.php

		[TestMethod]
		public void TestSamlResponseValidator()
		{
			var cert = @"-----BEGIN CERTIFICATE-----
MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==
-----END CERTIFICATE-----";

			var samlresp = new Saml.Response(cert);
			samlresp.LoadXml(@"<?xml version=""1.0""?>
<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""pfx6cdd04e4-f033-42ed-e74f-7ba72e2280e0"" Version=""2.0"" IssueInstant=""2014-07-17T01:01:48Z"" Destination=""http://sp.example.com/demo1/index.php?acs"" InResponseTo=""ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
    <ds:SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/>
  <ds:Reference URI=""#pfx6cdd04e4-f033-42ed-e74f-7ba72e2280e0""><ds:Transforms><ds:Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature""/><ds:Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/></ds:Transforms><ds:DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><ds:DigestValue>99Bke1BpL1yOfGd5ADkGSle2sZg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>OOyb3YtYQm3DC7gj6lQPM20r76HH4KvAE93f5xrIuIHGk8ZJlse4m8t4msLkhwUEAGwWOOVyHs8gChtN1m/P4pKCXyttO9Hev14Wz8E1R444kg5Yak+02FZ+Fn3VbbPq+kY4eYRkczNMphivWkdwc/QjDguNzGoKCEEtbBKDMGg=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xs=""http://www.w3.org/2001/XMLSchema"" ID=""_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"" Version=""2.0"" IssueInstant=""2014-07-17T01:01:48Z"">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier=""http://sp.example.com/demo1/metadata.php"" Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:transient"">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"">
        <saml:SubjectConfirmationData NotOnOrAfter=""2024-01-18T06:21:48Z"" Recipient=""http://sp.example.com/demo1/index.php?acs"" InResponseTo=""ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685""/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore=""2014-07-17T01:01:18Z"" NotOnOrAfter=""2024-01-18T06:21:48Z"">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant=""2014-07-17T01:01:48Z"" SessionNotOnOrAfter=""2024-07-17T09:01:48Z"" SessionIndex=""_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name=""uid"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"">
        <saml:AttributeValue xsi:type=""xs:string"">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name=""mail"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"">
        <saml:AttributeValue xsi:type=""xs:string"">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name=""eduPersonAffiliation"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"">
        <saml:AttributeValue xsi:type=""xs:string"">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type=""xs:string"">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
");

			samlresp.CurrentTime = new DateTime(2022, 3, 25);
			Assert.IsTrue(samlresp.IsValid());

			Assert.IsTrue(samlresp.GetNameID() == "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7");

			Assert.IsTrue(samlresp.GetEmail() == "test@example.com");

			Assert.IsTrue(samlresp.GetCustomAttribute("uid") == "test");
		}

		[TestMethod]
		public void TestSamlSignoutResponseValidator()
		{
			//this test's cert and signature borrowed from https://github.com/boxyhq/jackson/

			var cert = @"-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJcp0xLOhRU0fTMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFmRldi10eWo3cXl6ei5hdXRoMC5jb20wHhcNMTkwMzI3MTMyMTQ0WhcNMzIxMjAzMTMyMTQ0WjAhMR8wHQYDVQQDExZkZXYtdHlqN3F5enouYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyr2LHhkTEf5xO+mGjZascQ9bfzcSDmjyJ6RxfD9rAJorqVDIcq+dEtxDvo0HWt/bccX+9AZmMiqCclLRyv7Sley7BkxYra5ym8mTwmaZqUZbWyCQ15Hpq6G27yrWk8V6WKvMhJoxDqlgFh08QDOxBy5jCzwxVyFKDchJiy1TflLC8dFJLcmszQsrvl3enbQyYy9XejgniugJKElZMZknFF9LmcQWeCmwDG+2w6HcMZIXPny9Cl5GZra7wt/EWg3iwNw5ZqP41Hulf9fhilJs3bVehnDgftQTKyTUBEfCDxzaIsEmpPWAqTg5IIEKkHX4/1Rm+7ltxg+n0pIXxUrtCQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRcb2UMMqwD9zCk3DOWnx/XwfKd5DAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAFE1FG/u0eYHk/R5a8gGiPgazEjmQUSMlBxjhhTU8bc0X/oLyCfJGdoXQKJVtHgKAIcvCtrHBjKDy8CwSn+J1jTMZklnpkhvXUHiEj1ViplupwuXblvhEXR2+Bkly57Uy1qoFvKHCejayRWsDaG062kEQkt5k1FtVatUGS6labThHjr8K2RyqTAYpXWqthR+wKTFLni9V2pjuoUOABBYeGTalnIOGvr/i5I+IjJDHND0x7wrveekFDI5yX9V8ZdMGiN2SkoXBMa5+o1aD3gtbi8c2HcOgjMsIzHGAj4dz/0syWfpkEkrbs7FURSvtuRLaNrH/2/rto0KgiWWuPKvm1w=
-----END CERTIFICATE-----";

			var samlresp = new Saml.SignoutResponse(cert);
			samlresp.LoadXml(@"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_716cfa40a953610d9d68"" InResponseTo=""_a0089b303b86a97080ff"" Version=""2.0"" IssueInstant=""2022-03-25T07:50:52.110Z"" Destination=""http://localhost:3000/slo""><saml:Issuer xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">urn:dev-tyj7qyzz.auth0.com</saml:Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/><Reference URI=""#_716cfa40a953610d9d68""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature""/><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><DigestValue>Lk9TO/DGFFLLb+29H32O/scFccU=</DigestValue></Reference></SignedInfo><SignatureValue>altTmKkKqudi+jYBZd6bETdYRbTKerUiNxFugcoD7ZmdZsRlrcNir0ZLRq+NB6nTh4zeKwGiGs03FyAW0Wdr8vgl0GQ/KOGuUrpoFNI8EID1HYrghHZMR43CgauIHGg0dw8uSjQYUcU1ICVYG2trgXC9TR81g+3XVBPBnoJWS2yV8hPc6QdFAUdb/0qUn/GPdpSPOlb6/MMUQB+K+es6HzjQfU2PEV3aNarHrKHSyFRdBHFMgtt7rUE3eAev+3/Uwq6RPBFk9huUJ6F0MRDoVjpWNzD2jByTtRv7OYInDsEJKCwJ+6pOKGVK6GDXuXnuI8s6BNEalpNJkWR8BxFVbw==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBzCCAe+gAwIBAgIJcp0xLOhRU0fTMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFmRldi10eWo3cXl6ei5hdXRoMC5jb20wHhcNMTkwMzI3MTMyMTQ0WhcNMzIxMjAzMTMyMTQ0WjAhMR8wHQYDVQQDExZkZXYtdHlqN3F5enouYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyr2LHhkTEf5xO+mGjZascQ9bfzcSDmjyJ6RxfD9rAJorqVDIcq+dEtxDvo0HWt/bccX+9AZmMiqCclLRyv7Sley7BkxYra5ym8mTwmaZqUZbWyCQ15Hpq6G27yrWk8V6WKvMhJoxDqlgFh08QDOxBy5jCzwxVyFKDchJiy1TflLC8dFJLcmszQsrvl3enbQyYy9XejgniugJKElZMZknFF9LmcQWeCmwDG+2w6HcMZIXPny9Cl5GZra7wt/EWg3iwNw5ZqP41Hulf9fhilJs3bVehnDgftQTKyTUBEfCDxzaIsEmpPWAqTg5IIEKkHX4/1Rm+7ltxg+n0pIXxUrtCQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRcb2UMMqwD9zCk3DOWnx/XwfKd5DAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAFE1FG/u0eYHk/R5a8gGiPgazEjmQUSMlBxjhhTU8bc0X/oLyCfJGdoXQKJVtHgKAIcvCtrHBjKDy8CwSn+J1jTMZklnpkhvXUHiEj1ViplupwuXblvhEXR2+Bkly57Uy1qoFvKHCejayRWsDaG062kEQkt5k1FtVatUGS6labThHjr8K2RyqTAYpXWqthR+wKTFLni9V2pjuoUOABBYeGTalnIOGvr/i5I+IjJDHND0x7wrveekFDI5yX9V8ZdMGiN2SkoXBMa5+o1aD3gtbi8c2HcOgjMsIzHGAj4dz/0syWfpkEkrbs7FURSvtuRLaNrH/2/rto0KgiWWuPKvm1w=</X509Certificate></X509Data></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status></samlp:LogoutResponse>");
			Assert.IsTrue(samlresp.IsValid());

			Assert.IsTrue(samlresp.GetLogoutStatus() == "Success");
		}

		[TestMethod]
		public void TestSamlResponseValidatorAdvanced()
		{
			var cert = @"-----BEGIN CERTIFICATE-----
MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=
-----END CERTIFICATE-----";

			var samlresp = new Saml.Response(cert);
			samlresp.CurrentTime = new DateTime(2022, 3, 25);
			samlresp.LoadXml(@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" Destination=""http://localhost:5167/Home/SamlConsume"" ID=""ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae"" InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><dsig:Signature xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#""><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><dsig:SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><dsig:Reference URI=""#ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae""><dsig:Transforms><dsig:Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><dsig:Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></dsig:Transforms><dsig:DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><dsig:DigestValue>UrJzr9Ja0f4Ks+K6TPEfQ53bw1veGXHtMZpLmRrr/ww=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>EAM65nY/e0YkK/H0nw+hdt6PhUIEs5jtftvP/NuHCSFjsVNj8L4jIT7Gvso8r9gSnwz0FJetVK16LjHdN+0f8Od2BDk9njD7KBQx9v9ich12zl1Ny+T6dLtc4XypkvoPwscna7KIQOEn8xeKBq4IbC+gPYfJEQ3GjnQ5JuXhJW5GValLELKWbH21oECRL6VAs7BAohQy2/BbTTGM1tbeuqWIZrqdP/KKOpiHxVIPwzwC8EuQmrhYiaJ9tOzNtBJGD5IW7L6Z6GIhVX2yQPuEW/gfb/bYCi6+0KD664YBICfyJLSarbcK6qgafP9YUdJ48qopiHXbuZ1m8ceCfC0Kow==</dsig:SignatureValue><dsig:KeyInfo><dsig:X509Data><dsig:X509Certificate>MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=</dsig:X509Certificate></dsig:X509Data></dsig:KeyInfo></dsig:Signature><samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" /></samlp:Status><saml:Assertion xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""ID_4f3af568-ac8a-479f-ba5e-c41a665556cf"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><saml:Subject><saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">guest</saml:NameID><saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer""><saml:SubjectConfirmationData InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" NotOnOrAfter=""2024-01-18T16:18:33.039Z"" Recipient=""http://localhost:5167/Home/SamlConsume"" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=""2023-05-24T16:18:33.039Z"" NotOnOrAfter=""2024-01-18T16:18:33.039Z""><saml:AudienceRestriction><saml:Audience>WebApp3</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=""2023-05-24T16:18:35.039Z"" SessionIndex=""f954efd3-4332-4ff8-8cb7-8600174f22b0::f8e67f48-0a80-457e-a669-1e37bd0338d1"" SessionNotOnOrAfter=""2023-05-25T02:18:35.039Z""><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute FriendlyName=""email"" Name=""urn:oid:1.2.840.113549.1.9.1"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">guest@guest.com</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""surname"" Name=""urn:oid:2.5.4.4"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""givenName"" Name=""urn:oid:2.5.4.42"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">uma_authorization</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">offline_access</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">default-roles-poc</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">view-profile</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account-links</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">SimpleUser</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>");

			Assert.IsTrue(samlresp.IsValid());

			Assert.IsTrue(samlresp.GetCustomAttributeViaFriendlyName("givenName") == "Guest");

			Assert.IsTrue(Enumerable.SequenceEqual(samlresp.GetCustomAttributeAsList("Role"), new List<string> { "uma_authorization", "offline_access", "default-roles-poc", "view-profile", "manage-account", "manage-account-links", "SimpleUser" }));
		}

		[TestMethod]
		public void TestInvalidCertString()
		{
			//cert without the "-----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----"
			var cert = @"MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=";
			var samlresp = new Saml.Response(cert) { CurrentTime = new DateTime(2022, 3, 25) };
			samlresp.LoadXml(@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" Destination=""http://localhost:5167/Home/SamlConsume"" ID=""ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae"" InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><dsig:Signature xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#""><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><dsig:SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><dsig:Reference URI=""#ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae""><dsig:Transforms><dsig:Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><dsig:Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></dsig:Transforms><dsig:DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><dsig:DigestValue>UrJzr9Ja0f4Ks+K6TPEfQ53bw1veGXHtMZpLmRrr/ww=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>EAM65nY/e0YkK/H0nw+hdt6PhUIEs5jtftvP/NuHCSFjsVNj8L4jIT7Gvso8r9gSnwz0FJetVK16LjHdN+0f8Od2BDk9njD7KBQx9v9ich12zl1Ny+T6dLtc4XypkvoPwscna7KIQOEn8xeKBq4IbC+gPYfJEQ3GjnQ5JuXhJW5GValLELKWbH21oECRL6VAs7BAohQy2/BbTTGM1tbeuqWIZrqdP/KKOpiHxVIPwzwC8EuQmrhYiaJ9tOzNtBJGD5IW7L6Z6GIhVX2yQPuEW/gfb/bYCi6+0KD664YBICfyJLSarbcK6qgafP9YUdJ48qopiHXbuZ1m8ceCfC0Kow==</dsig:SignatureValue><dsig:KeyInfo><dsig:X509Data><dsig:X509Certificate>MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=</dsig:X509Certificate></dsig:X509Data></dsig:KeyInfo></dsig:Signature><samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" /></samlp:Status><saml:Assertion xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""ID_4f3af568-ac8a-479f-ba5e-c41a665556cf"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><saml:Subject><saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">guest</saml:NameID><saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer""><saml:SubjectConfirmationData InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" NotOnOrAfter=""2024-01-18T16:18:33.039Z"" Recipient=""http://localhost:5167/Home/SamlConsume"" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=""2023-05-24T16:18:33.039Z"" NotOnOrAfter=""2024-01-18T16:18:33.039Z""><saml:AudienceRestriction><saml:Audience>WebApp3</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=""2023-05-24T16:18:35.039Z"" SessionIndex=""f954efd3-4332-4ff8-8cb7-8600174f22b0::f8e67f48-0a80-457e-a669-1e37bd0338d1"" SessionNotOnOrAfter=""2023-05-25T02:18:35.039Z""><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute FriendlyName=""email"" Name=""urn:oid:1.2.840.113549.1.9.1"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">guest@guest.com</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""surname"" Name=""urn:oid:2.5.4.4"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""givenName"" Name=""urn:oid:2.5.4.42"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">uma_authorization</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">offline_access</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">default-roles-poc</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">view-profile</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account-links</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">SimpleUser</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>");
			Assert.IsTrue(samlresp.IsValid());
			Assert.IsTrue(samlresp.GetCustomAttributeViaFriendlyName("givenName") == "Guest");

			//without "-----END CERTIFICATE-----"
			cert = @"-----BEGIN CERTIFICATE-----
MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=";
			samlresp = new Saml.Response(cert) { CurrentTime = new DateTime(2022, 3, 25) };
			samlresp.LoadXml(@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" Destination=""http://localhost:5167/Home/SamlConsume"" ID=""ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae"" InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><dsig:Signature xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#""><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><dsig:SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><dsig:Reference URI=""#ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae""><dsig:Transforms><dsig:Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><dsig:Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></dsig:Transforms><dsig:DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><dsig:DigestValue>UrJzr9Ja0f4Ks+K6TPEfQ53bw1veGXHtMZpLmRrr/ww=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>EAM65nY/e0YkK/H0nw+hdt6PhUIEs5jtftvP/NuHCSFjsVNj8L4jIT7Gvso8r9gSnwz0FJetVK16LjHdN+0f8Od2BDk9njD7KBQx9v9ich12zl1Ny+T6dLtc4XypkvoPwscna7KIQOEn8xeKBq4IbC+gPYfJEQ3GjnQ5JuXhJW5GValLELKWbH21oECRL6VAs7BAohQy2/BbTTGM1tbeuqWIZrqdP/KKOpiHxVIPwzwC8EuQmrhYiaJ9tOzNtBJGD5IW7L6Z6GIhVX2yQPuEW/gfb/bYCi6+0KD664YBICfyJLSarbcK6qgafP9YUdJ48qopiHXbuZ1m8ceCfC0Kow==</dsig:SignatureValue><dsig:KeyInfo><dsig:X509Data><dsig:X509Certificate>MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=</dsig:X509Certificate></dsig:X509Data></dsig:KeyInfo></dsig:Signature><samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" /></samlp:Status><saml:Assertion xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""ID_4f3af568-ac8a-479f-ba5e-c41a665556cf"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><saml:Subject><saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">guest</saml:NameID><saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer""><saml:SubjectConfirmationData InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" NotOnOrAfter=""2024-01-18T16:18:33.039Z"" Recipient=""http://localhost:5167/Home/SamlConsume"" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=""2023-05-24T16:18:33.039Z"" NotOnOrAfter=""2024-01-18T16:18:33.039Z""><saml:AudienceRestriction><saml:Audience>WebApp3</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=""2023-05-24T16:18:35.039Z"" SessionIndex=""f954efd3-4332-4ff8-8cb7-8600174f22b0::f8e67f48-0a80-457e-a669-1e37bd0338d1"" SessionNotOnOrAfter=""2023-05-25T02:18:35.039Z""><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute FriendlyName=""email"" Name=""urn:oid:1.2.840.113549.1.9.1"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">guest@guest.com</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""surname"" Name=""urn:oid:2.5.4.4"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""givenName"" Name=""urn:oid:2.5.4.42"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">uma_authorization</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">offline_access</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">default-roles-poc</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">view-profile</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account-links</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">SimpleUser</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>");
			Assert.IsTrue(samlresp.IsValid());
			Assert.IsTrue(samlresp.GetCustomAttributeViaFriendlyName("givenName") == "Guest");

			//without "-----BEGIN CERTIFICATE-----"
			cert = @"MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=
-----END CERTIFICATE-----";
			samlresp = new Saml.Response(cert) { CurrentTime = new DateTime(2022, 3, 25) };
			samlresp.LoadXml(@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" Destination=""http://localhost:5167/Home/SamlConsume"" ID=""ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae"" InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><dsig:Signature xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#""><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><dsig:SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><dsig:Reference URI=""#ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae""><dsig:Transforms><dsig:Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><dsig:Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></dsig:Transforms><dsig:DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><dsig:DigestValue>UrJzr9Ja0f4Ks+K6TPEfQ53bw1veGXHtMZpLmRrr/ww=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>EAM65nY/e0YkK/H0nw+hdt6PhUIEs5jtftvP/NuHCSFjsVNj8L4jIT7Gvso8r9gSnwz0FJetVK16LjHdN+0f8Od2BDk9njD7KBQx9v9ich12zl1Ny+T6dLtc4XypkvoPwscna7KIQOEn8xeKBq4IbC+gPYfJEQ3GjnQ5JuXhJW5GValLELKWbH21oECRL6VAs7BAohQy2/BbTTGM1tbeuqWIZrqdP/KKOpiHxVIPwzwC8EuQmrhYiaJ9tOzNtBJGD5IW7L6Z6GIhVX2yQPuEW/gfb/bYCi6+0KD664YBICfyJLSarbcK6qgafP9YUdJ48qopiHXbuZ1m8ceCfC0Kow==</dsig:SignatureValue><dsig:KeyInfo><dsig:X509Data><dsig:X509Certificate>MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=</dsig:X509Certificate></dsig:X509Data></dsig:KeyInfo></dsig:Signature><samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" /></samlp:Status><saml:Assertion xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""ID_4f3af568-ac8a-479f-ba5e-c41a665556cf"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><saml:Subject><saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">guest</saml:NameID><saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer""><saml:SubjectConfirmationData InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" NotOnOrAfter=""2024-01-18T16:18:33.039Z"" Recipient=""http://localhost:5167/Home/SamlConsume"" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=""2023-05-24T16:18:33.039Z"" NotOnOrAfter=""2024-01-18T16:18:33.039Z""><saml:AudienceRestriction><saml:Audience>WebApp3</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=""2023-05-24T16:18:35.039Z"" SessionIndex=""f954efd3-4332-4ff8-8cb7-8600174f22b0::f8e67f48-0a80-457e-a669-1e37bd0338d1"" SessionNotOnOrAfter=""2023-05-25T02:18:35.039Z""><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute FriendlyName=""email"" Name=""urn:oid:1.2.840.113549.1.9.1"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">guest@guest.com</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""surname"" Name=""urn:oid:2.5.4.4"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""givenName"" Name=""urn:oid:2.5.4.42"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">uma_authorization</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">offline_access</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">default-roles-poc</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">view-profile</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account-links</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">SimpleUser</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>");
			Assert.IsTrue(samlresp.IsValid());
			Assert.IsTrue(samlresp.GetCustomAttributeViaFriendlyName("givenName") == "Guest");

		}

		[TestMethod]
		public void TestSamlRequest()
		{

			var request = new AuthRequest(
			  "http://www.myapp.com",
			  "http://www.myapp.com/SamlConsume"
			  );

			var r = request.GetRequest();

			//decode the compressed base64
			var ms = new MemoryStream(Convert.FromBase64String(r));
			var ds = new DeflateStream(ms, CompressionMode.Decompress, true);
			var output = new MemoryStream();
			ds.CopyTo(output);

			//get xml
			var str = Encoding.UTF8.GetString(output.ToArray());

			Assert.IsTrue(str.EndsWith(@"ProtocolBinding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" AssertionConsumerServiceURL=""http://www.myapp.com/SamlConsume"" xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""><saml:Issuer xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">http://www.myapp.com</saml:Issuer><samlp:NameIDPolicy Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"" AllowCreate=""true"" /></samlp:AuthnRequest>"));

		}

		[TestMethod]
		public void TestStringToByteArray()
		{
			//test that the old StringToByteArray was generating same result as the new Encoding.ASCII.GetBytes

			var cert = @"-----BEGIN CERTIFICATE-----
MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==
-----END CERTIFICATE-----";


			var x = StringToByteArray(cert);
			var y = Encoding.ASCII.GetBytes(cert);
			Assert.IsTrue(x.SequenceEqual(y));
		}

		[TestMethod]
		[DataRow(true)]
		[DataRow(false)]
		public void TestEncryptedAssertions(bool certificateContructor)
		{
			// SAML values from https://www.samltool.com/generic_sso_res.php.

			Saml.Response samlresp;
			if (certificateContructor)
			{
				var cert = Constants.Certificates.Certificate;
				samlresp = new Saml.Response(cert);
			}
			else
			{
				samlresp = new Saml.Response(Constants.Certificates.PublicCertificate, Constants.Certificates.PrivateKey, null);
			}


			var xml = @$"<?xml version=""1.0""?>
                        <samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"" Version=""2.0"" IssueInstant=""2014-07-17T01:01:48Z"" Destination=""http://sp.example.com/demo1/index.php?acs"" InResponseTo=""ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"">
                            <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
                            <samlp:Status>
                                <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
                            </samlp:Status>
                            <saml:EncryptedAssertion>
                                <xenc:EncryptedData xmlns:xenc=""http://www.w3.org/2001/04/xmlenc#"" xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#"" Type=""http://www.w3.org/2001/04/xmlenc#Element"">
	                                <xenc:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#aes128-cbc""/>
	                                <dsig:KeyInfo xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#"">
		                                <xenc:EncryptedKey>
			                                <xenc:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#rsa-1_5""/>
			                                <xenc:CipherData>
				                                <xenc:CipherValue>Pn5IVvMXk8cdvEJHQ0VGq9WMOaV2dg4QbuCdEt8Pc1yWZLUMlOghPK0pMevLsuKyBcUz/cIoQihsroBrQONrtLzhdqndGCtaZYoOdO2Lz0T5Huesqd6iEKihrtsLf4RGj2VX3XbtdQV5R/3IdnjGCgj4zClxtJb4P7gCApeQ/uIpjIuo/f1rwn9F0A+gbL5HOSicOrLMjTJVBwPR2EtwY1g7fomkKQtJpWiq2+LsXLoSwWIYM4wHyem6U+zX9qTr2yRefiNuyz1Ye0QCN1LXQCIYFrS0Mhao4MqXNXzkktmI1/FcAbGAwReUkAGY2UuS6+9MtPDuRFOk+8h+ldrxJBU=</xenc:CipherValue>
			                                </xenc:CipherData>
		                                </xenc:EncryptedKey>
	                                </dsig:KeyInfo>
	                                <xenc:CipherData>
		                                <xenc:CipherValue>WDObtBFd84WFugFF97T0SM3jd0QE6UPhVaiaLJsWRE9/rWN2oF7d0TfiYN9RmbcWYVMVdxl26o2QMX7nKv+ufesu+GSEMApKOKKjYqGYIWvSsnoeqZGoXftjl7+axLAt7XAqT4edh4IhaxM4k3aPdEFfc+fZVNzr9djUcOF7l7tFT29M0zeO/K/y6m9lvaWiRvdLf1K1Wqw8eramYvE7FhomwbIeWJguHznKrAfxhqw6HifIot/ox1pKpmyP49HLvq5tWQexTS+iNyktXzv0wZDOKjtfOy5xd5L8iXVBhY29a0tiFcnVrEWKZ7Z/kTKrl6uuxtiD6qOmlLQpcoSc1DeXnooBJn/PhIbsQZo6uKTtzMmRc62R3d32JZRUrg/Bpjtcb6nB4Iz4SSw4gSm4w7aNGKX3DqYpTAseEg082wtY4ZX8wTcb0pRV5Gc/h7vRNGtqD1q8/gmhQdpRZ468lg==</xenc:CipherValue>
	                                </xenc:CipherData>
                                </xenc:EncryptedData>
                            </saml:EncryptedAssertion>
                            <saml:EncryptedAssertion>
                                <xenc:EncryptedData xmlns:xenc=""http://www.w3.org/2001/04/xmlenc#"" xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#"" Type=""http://www.w3.org/2001/04/xmlenc#Element"">
	                                <xenc:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#aes128-cbc""/>
	                                <dsig:KeyInfo xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#"">
		                                <xenc:EncryptedKey>
			                                <xenc:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#rsa-1_5""/>
			                                <xenc:CipherData>
				                                <xenc:CipherValue>Pn5IVvMXk8cdvEJHQ0VGq9WMOaV2dg4QbuCdEt8Pc1yWZLUMlOghPK0pMevLsuKyBcUz/cIoQihsroBrQONrtLzhdqndGCtaZYoOdO2Lz0T5Huesqd6iEKihrtsLf4RGj2VX3XbtdQV5R/3IdnjGCgj4zClxtJb4P7gCApeQ/uIpjIuo/f1rwn9F0A+gbL5HOSicOrLMjTJVBwPR2EtwY1g7fomkKQtJpWiq2+LsXLoSwWIYM4wHyem6U+zX9qTr2yRefiNuyz1Ye0QCN1LXQCIYFrS0Mhao4MqXNXzkktmI1/FcAbGAwReUkAGY2UuS6+9MtPDuRFOk+8h+ldrxJBU=</xenc:CipherValue>
			                                </xenc:CipherData>
		                                </xenc:EncryptedKey>
	                                </dsig:KeyInfo>
	                                <xenc:CipherData>
		                                <xenc:CipherValue>WDObtBFd84WFugFF97T0SM3jd0QE6UPhVaiaLJsWRE9/rWN2oF7d0TfiYN9RmbcWYVMVdxl26o2QMX7nKv+ufesu+GSEMApKOKKjYqGYIWvSsnoeqZGoXftjl7+axLAt7XAqT4edh4IhaxM4k3aPdEFfc+fZVNzr9djUcOF7l7tFT29M0zeO/K/y6m9lvaWiRvdLf1K1Wqw8eramYvE7FhomwbIeWJguHznKrAfxhqw6HifIot/ox1pKpmyP49HLvq5tWQexTS+iNyktXzv0wZDOKjtfOy5xd5L8iXVBhY29a0tiFcnVrEWKZ7Z/kTKrl6uuxtiD6qOmlLQpcoSc1DeXnooBJn/PhIbsQZo6uKTtzMmRc62R3d32JZRUrg/Bpjtcb6nB4Iz4SSw4gSm4w7aNGKX3DqYpTAseEg082wtY4ZX8wTcb0pRV5Gc/h7vRNGtqD1q8/gmhQdpRZ468lg==</xenc:CipherValue>
	                                </xenc:CipherData>
                                </xenc:EncryptedData>
                            </saml:EncryptedAssertion>
                        </samlp:Response>";

			samlresp.LoadXml(xml);

			var attributes = samlresp.GetEncryptedAttributes();

			attributes.ShouldNotBeEmpty();

			var expectedValues = new[] {
				(ClaimTypes.MobilePhone, "555-555-1234"),
				(ClaimTypes.MobilePhone, "555-555-4321"),
				(ClaimTypes.MobilePhone, "555-555-1234"),
				(ClaimTypes.MobilePhone, "555-555-4321")
				};

			attributes.ShouldBe(expectedValues);

			// The results can be filtered by claim type.
			attributes.Where(x => x.Name == ClaimTypes.MobilePhone).ShouldBe(expectedValues);
			attributes.Where(x => x.Name == ClaimTypes.Email).ShouldBeEmpty();
		}

		[TestMethod]
		public void TestGetEncryptedAssertions()
		{
			// SAML values from https://www.samltool.com/generic_sso_res.php.

			string cert_pub_key = "MIIC8DCCAdigAwIBAgIQLPHm55AXUZ9F1GMB0uNm/jANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNDExMTUxMDAwMDlaFw0yNzExMTUxMDAwMTBaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq0SmPME4yJzRrbKeo7nLhFRs2nhp2+M+tVohYJBenHt70d4H4/rO/Qswi2yj+ATKU6xL+1k6/JsstEnzCEn254Z377Fz4dyS7odh5iKatxLUqBB+u2OfKhEPGlYHIgTEe1GOdnSSK9bCGVqbHSTEPnjzsbuytJ2FAHrHTtUb8/2Qt0RB28cfyxB2IuqJJwijT1ghStP1+VJcBDm5H7qtYRG4mvEhZwMD9ZmWbSnZVYz2MjWOwE+zGZhVQekWzW76M5S4S7YOdvDymyciP+GHAxOZPR9YLOJhjSJSCCXq8S5vMCVgDUP+zu+heH6L4oCPvNOfIzzJzIdTm7/5OH6E6QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAeHGxDWCh7cs5GbSedrpVb3Gl8l/KlwkcvLL6m5kBiJ9bbswqvC3lHFA6xKxQX2akZOijBgTMoBM3lSvIgeNFBREAYzqKA/GBX/MNyBgTnW4nDeL1/PKAQkSaSXUhh6jO+eYpsiRAeBYlCI8n5QvcI7mb2lpeFCD14zSb/v8lkaGJ/eQvoikD0+t/j8DsyVHqa+oLrIfdoWlfRb2dwkQxTF57g+NgnDknV/oPIuU+b2XeavR4eC3M9VAC4MHnbIwztTqAGYb78ipwsgdQpkF6zeTc6iW70RgCdXpPe7HXB807U6ISwqmtgqsyB5lH3UkWtSSuEjygMCYzKUl3VUkyA";
			string priv_key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD2KfeyDaGHkP7Gie32+1dPpcwkCxLmv916QJ5qWNoKo+0U7W38iASbmvSWinE7NwSZhnCQIWCaeDDkxz/cK9w3F5c2HGdgz1T/g6IB9Saq088xTLGVB59XIhbif2k4wyos8ZWXp6HqgDIVsqig2aUb91XKJHLCKyaHXKUEpbwIbwayvQqk5mJu4MaGOvPu8218XU2AnhuK544/aWFdhMBVhrvDkbkI0eVIhGxCmCVQEvqp/J0742/Gp2iSYNTMEPsqSDFBpoQOV8RsSmaVbqLiyfFudk1mzPBjEQreJc4swLKqIBCax7VxDCfmzQhd34eHMMxuLz1ax1xFoCwW2yrFAgMBAAECggEASZfoZoHuvcHaeW65BvLDeptduZTZ9MR9qVPySGcB4NZ7RZtqG2pqvj6ISw1eps5fAKsRsfVYlTXDoFH1RJSURKA348SAH5A8oBsxbxZklgO22M1N9fkOaRVW9CYVRhQK4t7i0zEZlir3TkdYZKZM11yNeF6HNIeEAEnxR79oxLgelVuQQx5dMKHfaDWAH5ucfjXvI8XH5vg4FkrnL5uFByKcDtSww/437Gl4j+lkhyVHMQp5FLxrwcN2SoOKEp4LJSbAo0KJ5CUJix9Bo7dGcVdGaetvMFI1Kp6u7uiFxknNDTaTvhF2NWp/7llDj8iEHiyO5IVS9E7+dL3cMLFnLQKBgQD8Gvapm8EhxLmelJW98vzRBHnSixnURTyIe/f4Azd7URD+m52YQl3qWssjnhKBPXupXGknxqhSPHjC/Fm7l+ogfNNFGZf4wc700/4cvEfAlkeQyZV4TBy8ZYMYEdE9KJHadH1fqARHvS9u6hFURw1JmKGanGavGPhVcmmwTPgJDwKBgQD594G8XtYlzR3QO0XaBmtkj8so/MuirzMduDgz6220MxjJHmEuZN02xnSiytTx84yPWUmVKobTZsiqtUvvWgPkmueNY6/umpdKwH3FqTbZMmuetFmqFNsQ3yBAx95xH/4kv9NB+KPvpPvkrnqi8jJRE9PXiHse+svXdvNQDMOG6wKBgDj9Y2s+AW+/x/I4Ro11A3/AkkVtGn6o1CFKXOjc2UrwLXZQ+VQ1FIPo2GkJz8cVfgHwGPlb6CsG7omtgB9vHQcRELVbLsaWEVG5JoWabmHz1uO9HiPemNRh4jurs3Au3qHSmZDpK2aINtPM5/P0R+WuMkIAPxov+9tdDNVE4QEzAoGBAPHuMazlhRKVEdPmalb4e5ya56DF+zl7pFeRYyQtKsKL6eNN+fTzPn+zWFPvSGbcuCBN5L/wpwmYo4NFcTc5wibSHmZkI3UmPmPlJlXWzvUsraivGVFaWiRcMFVCnPKUal+bIZbqVZCt9/Z/QMbQ7w41yIUE3VVAm2XxBNFnaR79AoGAU1XE3FEUlLJYqazpLyQ9xkplcfP9QB7kJwu7KnZyClZe37NyixM2INEw6e/ONdS+wrmAS7UDCh4szMb3VXsT6MMUZWeaTgGlipTwT+Xe+FptQtXD+v4VMfXM1TtScyTgMWvAMv/95DDPjBaSBwroh6gjrHOOJ6oHr7sq4hBshHw=";

			Saml.Response samlresp = new Saml.Response(cert_pub_key, priv_key, null);


			var xml = @$"<samlp:Response ID=""_01ef4503-5e20-4a68-9b1d-159e5e8262cb"" Version=""2.0"" IssueInstant=""2025-01-09T08:09:05.255Z"" Destination=""https://m5t-dev.meta-tools.com/login.aspx"" InResponseTo=""_1abe31b5-b600-4e3d-81dd-4c9099852231"" xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"">
	<Issuer xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"">https://sts.windows.net/fd182c57-7aca-49bf-807a-194fa00e2824/</Issuer>
	<samlp:Status>
		<samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
	</samlp:Status>
	<EncryptedAssertion xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"">
		<xenc:EncryptedData Type=""http://www.w3.org/2001/04/xmlenc#Element"" xmlns:xenc=""http://www.w3.org/2001/04/xmlenc#"">
			<xenc:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#aes256-cbc""/>
			<KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
				<e:EncryptedKey xmlns:e=""http://www.w3.org/2001/04/xmlenc#"">
					<e:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"">
						<DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/>
					</e:EncryptionMethod>
					<KeyInfo>
						<o:SecurityTokenReference xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
							<X509Data>
								<X509IssuerSerial>
									<X509IssuerName>CN=m5t-dev</X509IssuerName>
									<X509SerialNumber>83326181796178336741098593840416043364</X509SerialNumber>
								</X509IssuerSerial>
							</X509Data>
						</o:SecurityTokenReference>
					</KeyInfo>
					<e:CipherData>
						<e:CipherValue>nNoi4Z1HObRQKP7Qsw6F18RF1vhrvwh2AhDN+a3hn4YfcUPxRxH3vb8DNImonQ2E+uZGokbYBPMZ3jFiAz3gfxlTBg2fAMarGTv/Ok/Ibo2pvd9LVv2cnKEPrrcueANwyyRCaun4GKz5l2yEtHAImPZpVh0rIm69JtZqOrR7loW2bmfUKcxXBg45d2JS9+46vCqcE8L5dGqYsr81RJzL4tgVrf7wtzA+Xwkvw3W0ZncOdJh7s/nJx+KNitcuXoHyh4i4Uqk2Ebm0gkQGn3Svc4Px6lJulgD69w7tA2gEgL6MdIWAIblHNG9fFH1rxYSDI+dIDUVxWeR7892iTCrZaA==</e:CipherValue>
					</e:CipherData>
				</e:EncryptedKey>
			</KeyInfo>
			<xenc:CipherData>
				<xenc:CipherValue>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</xenc:CipherValue>
			</xenc:CipherData>
		</xenc:EncryptedData>
	</EncryptedAssertion>
</samlp:Response>";

			samlresp.LoadXml(xml);
			samlresp.AddDecryptedAssertions();

			Assert.IsTrue(samlresp.GetNameID() == "l.matthaeus@meta-five.com");
		}

		private static byte[] StringToByteArray(string st)
		{
			byte[] bytes = new byte[st.Length];
			for (int i = 0; i < st.Length; i++)
			{
				bytes[i] = (byte)st[i];
			}
			return bytes;
		}
	}
}
