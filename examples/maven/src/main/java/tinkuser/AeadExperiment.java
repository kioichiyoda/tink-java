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
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig2026;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

/**
 * AEAD (Authenticated Encryption with Associated Data) の基本動作を確認する実験用クラス.
 *
 * <p>以下の4つの挙動を検証します:
 *
 * <ol>
 *   <li>正常な暗号化と復号
 *   <li>暗号文の1ビット改ざん検知
 *   <li>関連データ (Associated Data) の不一致検知
 *   <li>ランダムIV（ノンス）による暗号化の非決定性
 * </ol>
 */
public final class AeadExperiment {
  private static String toHex(byte[] bytes, int maxBytes) {
    StringBuilder sb = new StringBuilder();
    int len = Math.min(bytes.length, maxBytes);
    for (int i = 0; i < len; i++) {
      sb.append(String.format("%02x", bytes[i] & 0xff));
    }
    return sb.toString();
  }

  public static void main(String[] args) throws GeneralSecurityException {
    System.out.println("==================================================");
    System.out.println("       Google Tink AEAD 実験デモプログラム");
    System.out.println("==================================================\n");

    // 1. 鍵セットの生成 (AES-128-GCM)
    KeysetHandle keysetHandle =
        KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM, AeadConfig2026.get());
    Aead aead = keysetHandle.getPrimitive(AeadConfig2026.get(), Aead.class);

    byte[] plaintext = "秘密のメッセージ: 口座残高は1000万円です".getBytes(UTF_8);
    byte[] associatedData = "accountId:user-12345".getBytes(UTF_8);

    System.out.println("[入力データ]");
    System.out.println(
        "  平文: " + new String(plaintext, UTF_8) + " (" + plaintext.length + " bytes)");
    System.out.println("  関連データ (AD): " + new String(associatedData, UTF_8));
    System.out.println();

    // ----------------------------------------------------
    // 実験 1: 正常な暗号化と復号
    // ----------------------------------------------------
    System.out.println("--- 実験 1: 正常な暗号化と復号 ---");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    System.out.println("  暗号化成功!");
    System.out.println("  暗号文サイズ: " + ciphertext.length + " bytes");
    System.out.println("  暗号文 (HEX先頭32B): " + toHex(ciphertext, 32) + "...");
    System.out.println("  暗号文 (Base64): " + Base64.getEncoder().encodeToString(ciphertext));

    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    System.out.println("  復号成功: \"" + new String(decrypted, UTF_8) + "\"");
    System.out.println("  元の平文と完全一致: " + Arrays.equals(plaintext, decrypted));
    System.out.println();

    // ----------------------------------------------------
    // 実験 2: 暗号文の1バイト改ざん実験
    // ----------------------------------------------------
    System.out.println("--- 実験 2: 暗号文の1バイト改ざん実験 ---");
    byte[] tamperedCiphertext = ciphertext.clone();
    // 暗号文の最後のバイトの1ビットを反転 (XOR 0x01)
    tamperedCiphertext[tamperedCiphertext.length - 1] ^= 0x01;
    System.out.println("  攻撃者が暗号文の末尾1ビットを書き換えました。");

    try {
      aead.decrypt(tamperedCiphertext, associatedData);
      System.out.println("  [警告] 復号できてしまいました（あってはならない状態）");
    } catch (GeneralSecurityException e) {
      System.out.println("  [検知成功!] 復号に失敗しました: " + e.getMessage());
      System.out.println("  -> 壊れた平文を漏らすことなく、即座に例外で弾かれました。");
    }
    System.out.println();

    // ----------------------------------------------------
    // 実験 3: 関連データ (Associated Data) の改ざん/すり替え実験
    // ----------------------------------------------------
    System.out.println("--- 実験 3: 関連データ (Associated Data) の不一致実験 ---");
    byte[] fakeAssociatedData = "accountId:attacker-99999".getBytes(UTF_8);
    System.out.println(
        "  別のユーザーのアカウントID ("
            + new String(fakeAssociatedData, UTF_8)
            + ") で復号を試みます。");

    try {
      aead.decrypt(ciphertext, fakeAssociatedData);
      System.out.println("  [警告] 復号できてしまいました（あってはならない状態）");
    } catch (GeneralSecurityException e) {
      System.out.println("  [検知成功!] 復号に失敗しました: " + e.getMessage());
      System.out.println("  -> 暗号文自体は無傷でも、文脈(AD)が一致しないため弾かれました。");
    }
    System.out.println();

    // ----------------------------------------------------
    // 実験 4: ランダムIV（同じ平文でも毎回暗号文が変わる）
    // ----------------------------------------------------
    System.out.println("--- 実験 4: 暗号化の非決定性（ランダムノンス） ---");
    byte[] ciphertext2 = aead.encrypt(plaintext, associatedData);
    System.out.println("  暗号文1 (先頭16B): " + toHex(ciphertext, 16) + "...");
    System.out.println("  暗号文2 (先頭16B): " + toHex(ciphertext2, 16) + "...");
    boolean isDifferent = !Arrays.equals(ciphertext, ciphertext2);
    System.out.println("  2つの暗号文は異なるか？: " + isDifferent);
    System.out.println(
        "  -> Tinkが毎回新しいIV(初期化ベクトル)を自動生成するため、盗聴者にパターンを推測されません。");
    System.out.println("\n==================================================");
  }

  private AeadExperiment() {}
}
