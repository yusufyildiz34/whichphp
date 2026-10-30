# PHP2Shell için barındırma firmanıza ne sormalısınız?

*[English](ask-your-host.md)*

Bu sayfa siteniz paylaşımlı ya da yönetilen bir barındırmadaysa ve sunucuya komut satırıyla erişiminiz yoksa sizin için. Sunucuyu kendiniz tarayamazsınız. Ama doğru soruları sorarak "korunuyoruz" yerine gerçek bir cevap alabilirsiniz.

## Bir dakikada arka plan

- **CVE-2026-109618 ve CVE-2026-109619 ("PHP2Shell")**, bir saldırganın PHP üzerinden sunucuda kod çalıştırmasına izin veriyor. PHP bunları 21 Ekim 2026'da 8.5.12, 8.4.27, 8.3.36 ve 8.2.35 sürümlerinde düzeltti.
- **CVE-2026-115560'ın henüz yaması yok.** Önlem, sunucuda `session.upload_progress.enabled` ayarını kapatmak.
- **PHP 8.1 ve daha eski sürümler resmi yama almıyor.** Onları ancak barındırma firmasının ya da bir sağlayıcının geri taşıdığı (backport) yama korur.
- **Barındırma firmaları yamayı çoğu zaman sürüm numarasını değiştirmeden uygular.** Bu yüzden panelinizdeki sürüm yamalı olduğu hâlde eski görünebilir. Tersi de olur: sürüm yeni görünür ama çalışan işlem hâlâ eskidir.

## Kopyalayıp gönderin

> Merhaba,
>
> **[alan adınız]** sitem için PHP güvenlik açıklarıyla ilgili sorularım var: CVE-2026-109618 ve CVE-2026-109619 (PHP2Shell, 21 Ekim 2026'da resmi olarak düzeltildi) ile CVE-2026-115560.
>
> 1. Sitemi hangi PHP sürümü ve tam olarak hangi derleme ya da paket sürümü çalıştırıyor?
> 2. Bu derleme CVE-2026-109618 ve CVE-2026-109619 için yamalı mı? Sürüm numarası 8.5.12, 8.4.27, 8.3.36 veya 8.2.35'ten eski görünüyorsa, yamayı içeren paket ya da derleme hangisi?
> 3. Güncellemeden sonra sitemi çalıştıran PHP işlemleri (PHP-FPM, LiteSpeed ya da Apache) ne zaman yeniden başlatıldı?
> 4. PHP, CVE-2026-115560'ı düzeltene kadar `session.upload_progress.enabled` ayarı sunucu genelinde (`php.ini` içinde ya da yönetici ayarı olarak) kapatıldı mı?
> 5. Sitem PHP 8.1 veya daha eski bir sürümde çalışıyorsa ne öneriyorsunuz: sürüm yükseltme mi, geri taşınmış bir yama mı? Yamaysa hangi sağlayıcıdan?
> 6. Kontrol paneliniz kendi PHP'sini kullanıyorsa o da güncellendi mi?
> 7. Güncellemeden önce siteme yönelik saldırı girişimi gördünüz mü? Gerekirse kayıtları (logları) saklayacak mısınız?
>
> Teşekkürler.

## Zayıf bir cevabın işaretleri

- **Sürüm ya da derleme bilgisi vermeden "korunuyoruz" veya "güvenlik duvarımız var" demek.** Güvenlik duvarı sadece yama yapılana kadar işe yarar.
- **Sadece sürüm numarası vermek.** Numara düzeltilmiş sürümlerden eskiyse derleme ya da paket bilgisi de gerekir.
- **"PHP 8.1 sorun değil" demek.** Bir geri taşıma yamasının adını vermiyorlarsa sorundur.
- **Yeniden başlatma sorusunu cevapsız bırakmak.** Kurulan güncelleme, çalışan işlemler yeniden başlatılana kadar etkisizdir.
- **Önlemi sadece hesabınızdaki `.user.ini` dosyasına koymak.** Birçok barındırma firması ve PHP'nin kendi açıklaması, bunun CVE-2026-115560 için geç kaldığını söylüyor. Ayar sunucu genelinde yapılmalı.

## Kendi başınıza neye bakabilirsiniz?

Barındırma firması olmadan yamayı kanıtlayamazsınız. Ama bunlar ipucu verir:

- **Kontrol panelinizdeki PHP sürüm seçici.** Sürüm dalını (8.3, 8.4…) gösterir. Yukarıdaki nedenlerle kanıt değildir.
- **Geçici bir `phpinfo()` sayfası.** İçinde `<?php phpinfo();` olan bir dosya yükleyin, bir kez açın, sonra **hemen silin**. Şunlara bakın:
  - PHP sürümü ve **Build Date** (derleme tarihi). 21 Ekim 2026 veya sonrası iyi bir işarettir ama kanıt değildir;
  - `session.upload_progress.enabled`, **Off** olmalı;
  - **Server API** satırı. Siteyi PHP-FPM'in mi, LiteSpeed'in mi, Apache'nin mi çalıştırdığını gösterir.
- **WordPress:** Araçlar → Site Sağlığı → Bilgi → Sunucu bölümü, sitenin kullandığı PHP sürümünü gösterir.

## Daha önce ele geçirilmiş olmaktan endişe ediyorsanız

- Herhangi bir yeniden kurulum ya da taşıma yapılmadan önce barındırma firmanızdan **kayıtları saklamasını** isteyin.
- Barındırma firmanızın rehberini ve [NCSC-NL PHP2Shell deposunu](https://github.com/NCSC-NL/php2shell) izleyin.
- Temiz bir tarama sonucu ya da "yamalı" bir sürüm, yamadan önce ne olduğu hakkında hiçbir şey söylemez.

---

*[whichphp](../README.md) projesinin parçasıdır. Düzeltmeler kaynak belirtilerek memnuniyetle kabul edilir.*
