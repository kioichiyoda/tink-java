// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package tinkuser;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.signature.SignatureConfig2026;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

/**
 * 公開鍵暗号によるデジタル署名 (PublicKeySign / PublicKeyVerify) の基本動作を確認する実験用クラス.
 *
 * <p>以下の5つの挙動を検証します:
 *
 * <ol>
 *   <li>Ed25519 秘密鍵の生成とデジタル署名の作成（および決定論的署名の確認）
 *   <li>公開鍵の安全な抽出・配布 (serializeKeysetWithoutSecret) と署名検証
 *   <li>文書改ざんの検知（完全性の保証）
 *   <li>第三者によるなりすまし署名の検知（真正性の保証）
 *   <li>署名鍵のローテーションと新旧署名の透過的検証
 * </ol>
 */
public final class SignatureExperiment {
  private static String toHex(byte[] bytes, int maxBytes) {
    StringBuilder sb = new StringBuilder();
    int len = Math.min(bytes.length, maxBytes);
    for (int i = 0; i < len; i++) {
      sb.append(String.format("%02x", bytes[i] & 0xff));
    }
    return sb.toString();
  }

  private static String formatKeyId(int keyId) {
    return String.format("%d (Hex: %08x)", Integer.toUnsignedLong(keyId), keyId);
  }

  public static void main(String[] args) throws GeneralSecurityException {
    System.out.println("==================================================");
    System.out.println("     Google Tink デジタル署名 (Ed25519) 実験デモ");
    System.out.println("==================================================\n");

    // ----------------------------------------------------
    // 実験 1: 秘密鍵の生成とデジタル署名の作成 (アリス側)
    // ----------------------------------------------------
    System.out.println("--- 実験 1: Ed25519 鍵ペアの生成と署名作成 (作成者: アリス) ---");
    KeysetHandle alicePrivateHandle =
        KeysetHandle.generateNew(PredefinedSignatureParameters.ED25519, SignatureConfig2026.get());
    int aliceKeyId = alicePrivateHandle.getPrimary().getId();
    System.out.println("  アリスの秘密鍵を生成しました。KeyId: " + formatKeyId(aliceKeyId));

    PublicKeySign signer =
        alicePrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class);

    byte[] document = "契約書: アリスはボブに100万円を支払うことに合意する".getBytes(UTF_8);
    byte[] signature = signer.sign(document);

    System.out.println("  対象文書: \"" + new String(document, UTF_8) + "\"");
    System.out.println(
        "  署名サイズ: "
            + signature.length
            + " bytes (5B Tinkヘッダー + 64B Ed25519署名)");
    System.out.println("  署名 (先頭16B HEX): " + toHex(signature, 16) + "...");
    System.out.println("  署名 (Base64): " + Base64.getEncoder().encodeToString(signature));

    // Ed25519 の特徴：署名時に乱数を使わない「決定論的署名」であるため、同じ文書には同じ署名が生成される
    byte[] signature2 = signer.sign(document);
    System.out.println(
        "  Ed25519 の決定論的署名確認 (2回の署名が完全一致するか): "
            + Arrays.equals(signature, signature2));
    System.out.println();

    // ----------------------------------------------------
    // 実験 2: 公開鍵の安全な抽出・配布と署名検証 (ボブ側)
    // ----------------------------------------------------
    System.out.println("--- 実験 2: 公開鍵の安全な抽出・配布と署名検証 (検証者: ボブ) ---");

    // もし誤って「秘密鍵」を公開用メソッドでシリアライズしようとしたらどうなるか？
    try {
      TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(
          alicePrivateHandle, SignatureConfig2026.get());
      System.out.println("  [警告] 秘密鍵がシリアライズできてしまいました");
    } catch (GeneralSecurityException e) {
      System.out.println("  [誤公開防止!] 秘密鍵を WithoutSecret で書き出そうとするとブロックされます: " + e.getMessage());
    }

    // 秘密鍵ハンドルから公開鍵ハンドルのみを安全に抽出
    KeysetHandle alicePublicHandle = alicePrivateHandle.getPublicKeysetHandle();

    // 公開鍵は秘密情報を含まないため、InsecureSecretKeyAccess 不要で JSON 化して配布可能
    String publicKeysetJson =
        TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(
            alicePublicHandle, SignatureConfig2026.get());
    System.out.println("  配布用・公開鍵 Keyset JSON (公開しても安全):");
    System.out.println("    " + publicKeysetJson.trim());

    // ボブ側：受け取った公開鍵 JSON を読み込み、PublicKeyVerify プリミティブを取得
    KeysetHandle bobReceivedPublicHandle =
        TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(
            publicKeysetJson, SignatureConfig2026.get());
    PublicKeyVerify verifier =
        bobReceivedPublicHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class);

    // 署名を検証（例外が投げられなければ検証成功）
    verifier.verify(signature, document);
    System.out.println("  [検証成功!] 文書は間違いなくアリスによって署名され、改ざんされていません。");
    System.out.println();

    // ----------------------------------------------------
    // 実験 3: 文書改ざんの検知 (完全性の検証)
    // ----------------------------------------------------
    System.out.println("--- 実験 3: 文書改ざんの検知実験 ---");
    byte[] tamperedDocument = "契約書: アリスはボブに900万円を支払うことに合意する".getBytes(UTF_8);
    System.out.println("  改ざんされた文書: \"" + new String(tamperedDocument, UTF_8) + "\"");

    try {
      verifier.verify(signature, tamperedDocument);
      System.out.println("  [警告] 改ざんされた文書の検証が通ってしまいました");
    } catch (GeneralSecurityException e) {
      System.out.println("  [検知成功!] 署名検証に失敗しました: " + e.getMessage());
      System.out.println("  -> 文書が1文字でも書き換えられると、ハッシュ値が変化し即座に拒否されます。");
    }
    System.out.println();

    // ----------------------------------------------------
    // 実験 4: なりすまし署名の検知 (真正性の検証)
    // ----------------------------------------------------
    System.out.println("--- 実験 4: 第三者（攻撃者）によるなりすまし署名の検知実験 ---");
    KeysetHandle attackerPrivateHandle =
        KeysetHandle.generateNew(PredefinedSignatureParameters.ED25519, SignatureConfig2026.get());
    PublicKeySign attackerSigner =
        attackerPrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class);
    byte[] forgedSignature = attackerSigner.sign(document);
    System.out.println("  攻撃者が自身の秘密鍵で同じ文書に署名を作成しました。");

    try {
      verifier.verify(forgedSignature, document);
      System.out.println("  [警告] なりすまし署名の検証が通ってしまいました");
    } catch (GeneralSecurityException e) {
      System.out.println("  [検知成功!] なりすまし署名を拒否しました: " + e.getMessage());
      System.out.println("  -> アリスの秘密鍵で作られた署名でなければ、アリスの公開鍵での検証は通りません。");
    }
    System.out.println();

    // ----------------------------------------------------
    // 実験 5: 署名鍵のローテーション (Ed25519 -> ECDSA P-256)
    // ----------------------------------------------------
    System.out.println("--- 実験 5: 署名鍵のローテーションと新旧署名の透過的検証 ---");
    KeysetHandle rotatedPrivateHandle =
        KeysetHandle.newBuilder(alicePrivateHandle)
            .setConfiguration(SignatureConfig2026.get())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(PredefinedSignatureParameters.ECDSA_P256)
                    .withRandomId()
                    .makePrimary())
            .build();

    PublicKeySign rotatedSigner =
        rotatedPrivateHandle.getPrimitive(SignatureConfig2026.get(), PublicKeySign.class);
    byte[] newDocument = "追加合意書: 支払期日を2026年12月末とする".getBytes(UTF_8);
    byte[] newSignature = rotatedSigner.sign(newDocument);

    // 新旧2つの公開鍵を含む公開鍵セットをボブに配布
    KeysetHandle rotatedPublicHandle = rotatedPrivateHandle.getPublicKeysetHandle();
    PublicKeyVerify rotatedVerifier =
        rotatedPublicHandle.getPrimitive(SignatureConfig2026.get(), PublicKeyVerify.class);

    rotatedVerifier.verify(signature, document);
    System.out.println("  [旧署名 (Ed25519) の検証] 成功!");
    rotatedVerifier.verify(newSignature, newDocument);
    System.out.println("  [新署名 (ECDSA P-256) の検証] 成功!");
    System.out.println("  -> 公開鍵セットを更新するだけで、過去の署名も新しい署名も単一の Verifier で検証可能！");

    System.out.println("\n==================================================");
  }

  private SignatureExperiment() {}
}
