<?php
/**
 * Static AAGUID-to-model registry for WebAuthn authenticators.
 *
 * Maps known authenticator AAGUIDs to a human-readable model label and an
 * icon class ('key' = roaming hardware key, 'device' = platform/synced
 * passkey provider). Used purely for display in the security-key manager
 * — never for policy decisions, so an unknown AAGUID simply renders the
 * generic label.
 *
 * Sources: Yubico entries from the FIDO Alliance Metadata Service (MDS v3,
 * retrieved 2026-08-05); platform providers from the community
 * passkey-authenticator-aaguids list. Model names are trimmed of MDS
 * profile suffixes. Refresh by regenerating from MDS when new hardware
 * ships — the list is static by design (no runtime fetch, no cron).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.35
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AAGUID lookup for authenticator model labels.
 *
 * @since 2.1.35
 */
final class ReportedIP_Hive_WebAuthn_Aaguid_Registry {

	/**
	 * AAGUID => array( model label, icon type ).
	 *
	 * @var array<string,array{0:string,1:string}>
	 */
	private const MODELS = array(
		'760eda36-00aa-4d29-855b-4012a182cdeb' => array( 'Security Key NFC by Yubico', 'key' ),
		'a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa' => array( 'Security Key NFC by Yubico', 'key' ),
		'b7d3f68e-88a6-471e-9ecf-2df26d041ede' => array( 'Security Key NFC by Yubico', 'key' ),
		'e77e3c64-05e3-428b-8824-0cbeb04b829d' => array( 'Security Key NFC by Yubico', 'key' ),
		'0bb43545-fd2c-4185-87dd-feb0b2916ace' => array( 'Security Key NFC by Yubico - Enterprise Edition', 'key' ),
		'2772ce93-eb4b-4090-8b73-330f48477d73' => array( 'Security Key NFC by Yubico - Enterprise Edition', 'key' ),
		'47ab2fb4-66ac-4184-9ae1-86be814012d5' => array( 'Security Key NFC by Yubico - Enterprise Edition', 'key' ),
		'72c6b72d-8512-4c66-8359-9d3d10d9222f' => array( 'Security Key NFC by Yubico - Enterprise Edition', 'key' ),
		'9ff4cc65-6154-4fff-ba09-9e2af7882ad2' => array( 'Security Key NFC by Yubico - Enterprise Edition', 'key' ),
		'ed042a3a-4b22-4455-bb69-a267b652ae7e' => array( 'Security Key NFC by Yubico - Enterprise Edition', 'key' ),
		'b92c3f9a-c014-4056-887f-140a2501163b' => array( 'Security Key by Yubico', 'key' ),
		'f8a011f3-8c0a-4d15-8006-17111f9edc7d' => array( 'Security Key by Yubico', 'key' ),
		'149a2021-8ef6-4133-96b8-81f8d5b7f1f5' => array( 'Security Key by Yubico with NFC', 'key' ),
		'6d44ba9b-f6ec-2e49-b930-0c8fe920cb73' => array( 'Security Key by Yubico with NFC', 'key' ),
		'3aa78eb1-ddd8-46a8-a821-8f8ec57a7bd5' => array( 'YubiKey 5 CCN Series with NFC', 'key' ),
		'3ec9c8d3-a5a7-415b-a7b5-f1d606368d3f' => array( 'YubiKey 5 CCN Series with NFC', 'key' ),
		'4fc84f16-2545-4e53-b8fc-7bf4d7282a10' => array( 'YubiKey 5 CCN Series with NFC', 'key' ),
		'eb7ef748-cbe0-4b40-b8f6-07bd2d592d35' => array( 'YubiKey 5 CCN Series with NFC', 'key' ),
		'57f7de54-c807-4eab-b1c6-1c9be7984e92' => array( 'YubiKey 5 FIPS Series', 'key' ),
		'73bb0cd4-e502-49b8-9c6f-b59445bf720b' => array( 'YubiKey 5 FIPS Series', 'key' ),
		'905b4cb4-ed6f-4da9-92fc-45e0d4e9b5c7' => array( 'YubiKey 5 FIPS Series', 'key' ),
		'd2fbd093-ee62-488d-9dad-1e36389f8826' => array( 'YubiKey 5 FIPS Series (RC)', 'key' ),
		'3a662962-c6d4-4023-bebb-98ae92e78e20' => array( 'YubiKey 5 FIPS Series with Lightning', 'key' ),
		'5b0e46ba-db02-44ac-b979-ca9b84f5e335' => array( 'YubiKey 5 FIPS Series with Lightning', 'key' ),
		'7b96457d-e3cd-432b-9ceb-c9fdd7ef7432' => array( 'YubiKey 5 FIPS Series with Lightning', 'key' ),
		'85203421-48f9-4355-9bc8-8a53846e5083' => array( 'YubiKey 5 FIPS Series with Lightning', 'key' ),
		'9e66c661-e428-452a-a8fb-51f7ed088acf' => array( 'YubiKey 5 FIPS Series with Lightning (RC)', 'key' ),
		'62e54e98-c209-4df3-b692-de71bb6a8528' => array( 'YubiKey 5 FIPS Series with NFC', 'key' ),
		'79f3c8ba-9e35-484b-8f47-53a5a0f5c630' => array( 'YubiKey 5 FIPS Series with NFC', 'key' ),
		'c1f9a0bc-1dd2-404a-b27f-8e29047a43fd' => array( 'YubiKey 5 FIPS Series with NFC', 'key' ),
		'fcc0118f-cd45-435b-8da1-9782b2da0715' => array( 'YubiKey 5 FIPS Series with NFC', 'key' ),
		'ce6bf97f-9f69-4ba7-9032-97adc6ca5cf1' => array( 'YubiKey 5 FIPS Series with NFC (RC)', 'key' ),
		'0a357157-9b18-4c8a-920e-d156e972b2f8' => array( 'YubiKey 5 Series', 'key' ),
		'19083c3d-8383-4b18-bc03-8f1c9ab2fd1b' => array( 'YubiKey 5 Series', 'key' ),
		'20ac7a17-c814-4833-93fe-539f0d5e3389' => array( 'YubiKey 5 Series', 'key' ),
		'4599062e-6926-4fe7-9566-9e8fb1aedaa0' => array( 'YubiKey 5 Series', 'key' ),
		'524de2de-982f-49b4-a769-2b5e3b73ad79' => array( 'YubiKey 5 Series', 'key' ),
		'cb69481e-8ff7-4039-93ec-0a2729a154a8' => array( 'YubiKey 5 Series', 'key' ),
		'ee882879-721c-4913-9775-3dfcce97072a' => array( 'YubiKey 5 Series', 'key' ),
		'ff4dac45-ede8-4ec2-aced-cf66103f4335' => array( 'YubiKey 5 Series', 'key' ),
		'03012cb7-4fb2-42e7-9e8d-a81f10e2a5e9' => array( 'YubiKey 5 Series with Lightning', 'key' ),
		'24673149-6c86-42e7-98d9-433fb5b73296' => array( 'YubiKey 5 Series with Lightning', 'key' ),
		'3124e301-f14e-4e38-876d-fbeeb090e7bf' => array( 'YubiKey 5 Series with Lightning', 'key' ),
		'3b24bf49-1d45-4484-a917-13175df0867b' => array( 'YubiKey 5 Series with Lightning', 'key' ),
		'a02167b9-ae71-4ac7-9a07-06432ebb6f1c' => array( 'YubiKey 5 Series with Lightning', 'key' ),
		'b90e7dc1-316e-4fee-a25a-56a666a670fe' => array( 'YubiKey 5 Series with Lightning', 'key' ),
		'c3479970-e58a-4f70-836f-853bf42fb063' => array( 'YubiKey 5 Series with Lightning', 'key' ),
		'c5ef55ff-ad9a-4b9f-b580-adebafe026d0' => array( 'YubiKey 5 Series with Lightning', 'key' ),
		'1ac71f64-468d-4fe0-bef1-0e5f2f551f18' => array( 'YubiKey 5 Series with NFC', 'key' ),
		'2fc0579f-8113-47ea-b116-bb5a8db9202a' => array( 'YubiKey 5 Series with NFC', 'key' ),
		'34f5766d-1536-4a24-9033-0e294e510fb0' => array( 'YubiKey 5 Series with NFC', 'key' ),
		'41e39911-c669-4811-b860-c6ad0b411b96' => array( 'YubiKey 5 Series with NFC', 'key' ),
		'6ab56fad-881f-4a43-acb2-0be065924522' => array( 'YubiKey 5 Series with NFC', 'key' ),
		'a25342c0-3cdc-4414-8e46-f4807fca511c' => array( 'YubiKey 5 Series with NFC', 'key' ),
		'd7781e5d-e353-46aa-afe2-3ca49f13332a' => array( 'YubiKey 5 Series with NFC', 'key' ),
		'f4ce5fc0-57d3-46f5-a736-efb7d5bc63b5' => array( 'YubiKey 5 Series with NFC', 'key' ),
		'fa2b99dc-9e39-4257-8f92-4a30d23c4118' => array( 'YubiKey 5 Series with NFC', 'key' ),
		'662ef48a-95e2-4aaa-a6c1-5b9c40375824' => array( 'YubiKey 5 Series with NFC - Enhanced PIN', 'key' ),
		'b2c1a50b-dad8-4dc7-ba4d-0ce9597904bc' => array( 'YubiKey 5 Series with NFC - Enhanced PIN', 'key' ),
		'0ebd9f2c-f685-441c-8c3e-a02a234a840a' => array( 'YubiKey 5 Series with NFC Enhanced PIN', 'key' ),
		'9a3f2abd-a73d-439c-9ee7-1b53a857eaa7' => array( 'YubiKey 5 Series with NFC Enhanced PIN', 'key' ),
		'9eb7eabc-9db5-49a1-b6c3-555a802093f4' => array( 'YubiKey 5 Series with NFC KVZR57', 'key' ),
		'7dab85a5-d16d-4eaf-a7ef-4c1385b151c5' => array( 'YubiKey 5 Series with NFC KVZR57-2', 'key' ),
		'9dd8d593-2213-438a-97f8-d6b813d51c27' => array( 'YubiKey Bio Fido Edition', 'key' ),
		'add92433-0d69-4026-8166-29b25bce64e9' => array( 'YubiKey Bio Fido Edition', 'key' ),
		'ba0a9266-40d8-4048-9786-d710b5474752' => array( 'YubiKey Bio Multi-protocol Edition', 'key' ),
		'dc5e949d-f939-43b3-9877-a85c7186b753' => array( 'YubiKey Bio Multi-protocol Edition', 'key' ),
		'9806a2c8-c0da-478e-b4ca-620005d34182' => array( 'YubiKey Bio Multi-protocol Edition 1VDJSN-2', 'key' ),
		'7409272d-1ff9-4e10-9fc9-ac0019c124fd' => array( 'YubiKey Bio Series - FIDO Edition', 'key' ),
		'83c47309-aabb-4108-8470-8be838b573cb' => array( 'YubiKey Bio Series - FIDO Edition', 'key' ),
		'8c39ee86-7f9a-4a95-9ba3-f6b097e5c2ee' => array( 'YubiKey Bio Series - FIDO Edition', 'key' ),
		'ad08c78a-4e41-49b9-86a2-ac15b06899e2' => array( 'YubiKey Bio Series - FIDO Edition', 'key' ),
		'd8522d9f-575b-4866-88a9-ba99fa02f35b' => array( 'YubiKey Bio Series - FIDO Edition', 'key' ),
		'dd86a2da-86a0-4cbe-b462-4bd31f57bc6f' => array( 'YubiKey Bio Series - FIDO Edition', 'key' ),
		'34744913-4f57-4e6e-a527-e9ec3c4b94e6' => array( 'YubiKey Bio Series - Multi-protocol Edition', 'key' ),
		'6ec5cff2-a0f9-4169-945b-f33b563f7b99' => array( 'YubiKey Bio Series - Multi-protocol Edition', 'key' ),
		'7d1351a6-e097-4852-b8bf-c9ac5c9ce4a3' => array( 'YubiKey Bio Series - Multi-protocol Edition', 'key' ),
		'90636e1f-ef82-43bf-bdcf-5255f139d12f' => array( 'YubiKey Bio Series - Multi-protocol Edition', 'key' ),
		'97e6a830-c952-4740-95fc-7c78dc97ce47' => array( 'YubiKey Bio Series - Multi-protocol Edition', 'key' ),
		'58276709-bb4b-4bb3-baf1-60eea99282a7' => array( 'YubiKey Bio Series - Multi-protocol Edition 1VDJSN', 'key' ),

		'bada5566-a7aa-401f-bd96-45619a55120d' => array( '1Password', 'device' ),
		'd548826e-79b4-db40-a3d8-11116f7e8349' => array( 'Bitwarden', 'device' ),
		'adce0002-35bc-c60a-648b-0b25f1f05503' => array( 'Chrome on Mac', 'device' ),
		'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' => array( 'Google Password Manager', 'device' ),
		'53414d53-554e-4700-0000-000000000000' => array( 'Samsung Pass', 'device' ),
		'08987058-cadc-4b81-b6e1-30de50dcbe96' => array( 'Windows Hello', 'device' ),
		'6028b017-b1d4-4c02-b4b3-afcdafc96bb2' => array( 'Windows Hello', 'device' ),
		'9ddd1817-af5a-4672-a2b9-3e3dd95000a9' => array( 'Windows Hello', 'device' ),
		'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' => array( 'iCloud Keychain', 'device' ),
		'dd4ec289-e01d-41c9-bb89-70fa845d4bf2' => array( 'iCloud Keychain (Managed)', 'device' ),
	);

	/**
	 * Resolve an AAGUID to a display descriptor.
	 *
	 * @param string $aaguid Lower-case dashed AAGUID.
	 * @return array{label:string,icon:string}|null Null when unknown (or the
	 *                                              zero AAGUID sent under
	 *                                              attestation "none").
	 */
	public static function lookup( $aaguid ) {
		$aaguid = strtolower( (string) $aaguid );
		if ( '' === $aaguid || '00000000-0000-0000-0000-000000000000' === $aaguid ) {
			return null;
		}
		if ( ! isset( self::MODELS[ $aaguid ] ) ) {
			return null;
		}
		return array(
			'label' => self::MODELS[ $aaguid ][0],
			'icon'  => self::MODELS[ $aaguid ][1],
		);
	}
}
