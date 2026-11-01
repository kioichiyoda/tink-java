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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig2026;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Keyset（鍵セット）と鍵ローテーション、および安全な保存方法を検証する実験用クラス.
 *
 * <p>以下のライフサイクルを検証します:
 *
 * <ol>
 *   <li>初期状態（鍵Aのみ）での暗号化
 *   <li>新鍵B の追加と Primary への昇格（鍵ローテーション）
 *   <li>ローテーション後における新旧データの透過的な復号
 *   <li>Keyset の保存と復元（平文シリアライズと、本番推奨のエンベロープ暗号化）
 *   <li>旧鍵A の無効化 (DISABLED) と削除 (deleteAt) によるアクセス遮断
 * </ol>
 */
public final class KeysetRotationExperiment {
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

  private static void printKeysetSummary(String label, KeysetHandle handle) {
    System.out.println("  " + label + " (キー数: " + handle.size() + ")");
    for (int i = 0; i < handle.size(); i++) {
      KeysetHandle.Entry entry = handle.getAt(i);
      System.out.println(
          "    - Entry["
              + i
              + "] KeyId: "
              + formatKeyId(entry.getId())
              + ", Status: "
              + entry.getStatus()
              + ", isPrimary: "
              + entry.isPrimary());
    }
  }

  public static void main(String[] args) throws GeneralSecurityException {
    System.out.println("==================================================");
    System.out.println("    Google Tink 鍵ローテーション・Keyset 実験デモ");
    System.out.println("==================================================\n");

    byte[] associatedData = "context:customer-db".getBytes(UTF_8);

    // ----------------------------------------------------
    // Phase 1: 初代の鍵セット（鍵A のみで運用開始）
    // ----------------------------------------------------
    System.out.println("--- Phase 1: 初期鍵セット (鍵A) の生成とデータ暗号化 ---");
    KeysetHandle handleV1 =
        KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM, AeadConfig2026.get());
    int keyIdA = handleV1.getPrimary().getId();
    printKeysetSummary("鍵セットV1", handleV1);

    Aead aeadV1 = handleV1.getPrimitive(AeadConfig2026.get(), Aead.class);
    byte[] plaintextOld = "2024年の重要データ: 顧客Aの残高100万円".getBytes(UTF_8);
    byte[] ciphertextOld = aeadV1.encrypt(plaintextOld, associatedData);
    System.out.println("  過去データを暗号化しました。");
    System.out.println(
        "  暗号文 (先頭5Bヘッダー): "
            + toHex(ciphertextOld, 5)
            + " (先頭バイト: 01, 鍵ID: "
            + String.format("%08x", keyIdA)
            + ")");
    System.out.println();

    // ----------------------------------------------------
    // Phase 2: 鍵のローテーション（新鍵B を追加して Primary に昇格）
    // ----------------------------------------------------
    System.out.println("--- Phase 2: 鍵ローテーションの実行 ---");
    System.out.println("  運用ポリシーに従い、新鍵B (AES-256-GCM) を追加して Primary に切り替えます。");
    KeysetHandle handleV2 =
        KeysetHandle.newBuilder(handleV1)
            .setConfiguration(AeadConfig2026.get())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(PredefinedAeadParameters.AES256_GCM)
                    .withRandomId()
                    .makePrimary())
            .build();

    int keyIdB = handleV2.getPrimary().getId();
    printKeysetSummary("鍵セットV2", handleV2);
    System.out.println();

    // ----------------------------------------------------
    // Phase 3: ローテーション後の暗号化と「透過的復号」の検証
    // ----------------------------------------------------
    System.out.println("--- Phase 3: 新鍵での暗号化 ＆ 新旧データの透過的復号 ---");
    Aead aeadV2 = handleV2.getPrimitive(AeadConfig2026.get(), Aead.class);

    // 新規データの暗号化
    byte[] plaintextNew = "2025年の新規データ: 顧客Bの残高500万円".getBytes(UTF_8);
    byte[] ciphertextNew = aeadV2.encrypt(plaintextNew, associatedData);
    System.out.println("  新規データを暗号化しました。");
    System.out.println(
        "  新規暗号文 (先頭5Bヘッダー): "
            + toHex(ciphertextNew, 5)
            + " -> 自動で新鍵B ("
            + String.format("%08x", keyIdB)
            + ") が使われました。");

    // 過去データ（鍵Aで暗号化）の復号テスト
    byte[] decryptedOld = aeadV2.decrypt(ciphertextOld, associatedData);
    System.out.println(
        "  [旧データ復号] 成功: \""
            + new String(decryptedOld, UTF_8)
            + "\" (一致: "
            + Arrays.equals(plaintextOld, decryptedOld)
            + ")");

    // 新規データ（鍵Bで暗号化）の復号テスト
    byte[] decryptedNew = aeadV2.decrypt(ciphertextNew, associatedData);
    System.out.println(
        "  [新データ復号] 成功: \""
            + new String(decryptedNew, UTF_8)
            + "\" (一致: "
            + Arrays.equals(plaintextNew, decryptedNew)
            + ")");
    System.out.println(
        "  -> アプリケーションは暗号文ヘッダーを気にせず、同一の AEAD インスタンスで新旧両方を復号可能！");
    System.out.println();

    // ----------------------------------------------------
    // Phase 4: Keyset の保存と復元（エンベロープ暗号化 vs 平文）
    // ----------------------------------------------------
    System.out.println("--- Phase 4: Keyset の安全な保存 (エンベロープ暗号化) と復元 ---");

    // 4-1. 本番推奨：KMS 等の鍵暗号化鍵 (KEK) を使ったエンベロープ暗号化
    KeysetHandle kekHandle =
        KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM, AeadConfig2026.get());
    Aead kekAead = kekHandle.getPrimitive(AeadConfig2026.get(), Aead.class);
    byte[] keysetAssociatedData = "keyset:customer-db-aead".getBytes(UTF_8);

    String encryptedKeysetJson =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            handleV2, kekAead, keysetAssociatedData, AeadConfig2026.get());
    System.out.println("  [本番推奨] エンベロープ暗号化された Keyset JSON:");
    System.out.println("    " + encryptedKeysetJson.trim());
    System.out.println(
        "    -> 鍵本体は encryptedKeyset に暗号化され、keysetInfo には鍵IDやステータスのみが含まれます。");

    KeysetHandle restoredFromEncrypted =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            encryptedKeysetJson, kekAead, keysetAssociatedData, AeadConfig2026.get());
    Aead restoredAead = restoredFromEncrypted.getPrimitive(AeadConfig2026.get(), Aead.class);
    byte[] restoredDecrypted = restoredAead.decrypt(ciphertextOld, associatedData);
    System.out.println(
        "  暗号化 Keyset からの復元・復号テスト: 成功 (\""
            + new String(restoredDecrypted, UTF_8)
            + "\")");

    // 4-2. 開発・テスト用：InsecureSecretKeyAccess を明示した平文シリアライズ
    String cleartextKeysetJson =
        TinkJsonProtoKeysetFormat.serializeKeyset(
            handleV2, AeadConfig2026.get(), InsecureSecretKeyAccess.get());
    KeysetHandle restoredFromCleartext =
        TinkJsonProtoKeysetFormat.parseKeyset(
            cleartextKeysetJson, AeadConfig2026.get(), InsecureSecretKeyAccess.get());
    System.out.println(
        "  [開発用] 平文 Keyset からの復元キー数: " + restoredFromCleartext.size() + " (要 InsecureSecretKeyAccess)");
    System.out.println();

    // ----------------------------------------------------
    // Phase 5: 旧鍵A の無効化 (DISABLED) と完全削除 (deleteAt)
    // ----------------------------------------------------
    System.out.println("--- Phase 5: 旧鍵A の無効化 (DISABLED) と完全削除 (deleteAt) ---");

    // 5-1. まず旧鍵A (Entry[0]) を DISABLED に変更して一時無効化
    KeysetHandle.Builder disableBuilder = KeysetHandle.newBuilder(handleV2);
    disableBuilder.getAt(0).setStatus(KeyStatus.DISABLED);
    KeysetHandle handleDisabledA = disableBuilder.build();
    printKeysetSummary("旧鍵Aを DISABLED にした鍵セット", handleDisabledA);

    Aead aeadDisabledA = handleDisabledA.getPrimitive(AeadConfig2026.get(), Aead.class);
    try {
      aeadDisabledA.decrypt(ciphertextOld, associatedData);
      System.out.println("  [警告] DISABLED の鍵Aのデータが復号できてしまいました");
    } catch (GeneralSecurityException e) {
      System.out.println("  [期待通りエラー!] DISABLED 状態の鍵Aのデータは復号拒否: " + e.getMessage());
    }

    // 5-2. 旧データの新鍵への再暗号化移行が完了した後、deleteAt(0) で旧鍵Aを完全に削除
    KeysetHandle handleDeletedA = KeysetHandle.newBuilder(handleV2).deleteAt(0).build();
    printKeysetSummary("旧鍵Aを deleteAt(0) で削除した鍵セット", handleDeletedA);

    Aead aeadDeletedA = handleDeletedA.getPrimitive(AeadConfig2026.get(), Aead.class);
    byte[] okDecrypted = aeadDeletedA.decrypt(ciphertextNew, associatedData);
    System.out.println(
        "  新鍵Bで暗号化したデータ: 正常に復号可能 (\"" + new String(okDecrypted, UTF_8) + "\")");

    try {
      aeadDeletedA.decrypt(ciphertextOld, associatedData);
      System.out.println("  [警告] 削除された鍵Aのデータが復号できてしまいました");
    } catch (GeneralSecurityException e) {
      System.out.println("  [期待通りエラー!] 削除された鍵Aのデータは復号拒否: " + e.getMessage());
      System.out.println("  -> 旧鍵の無効化 (DISABLED) から完全削除 (deleteAt) まで安全に完了しました。");
    }

    System.out.println("\n==================================================");
  }

  private KeysetRotationExperiment() {}
}
