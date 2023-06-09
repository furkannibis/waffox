# WAFFOX
Bu proje, bir web uygulaması güvenlik duvarı (WAF) oluşturmayı amaçlamaktadır. WAF, web uygulamalarını çeşitli saldırılara karşı korumak için kullanılan bir güvenlik önlemidir. Bu projenin amacı, gelişmiş makine öğrenmesi algoritmalarını kullanarak potansiyel saldırıları tespit etmek ve engellemek için bir WAF oluşturmaktır. WAF, web uygulamalarının güvenliğini artırarak kullanıcı bilgilerinin ve sistem bütünlüğünün korunmasına yardımcı olur.

## PROJE ÖZELLİKLERİ:
Bu proje, çeşitli önemli özelliklere sahiptir:

- **Veri seti işleme**: Proje, pandas kütüphanesini kullanarak veri setini işlemektedir. Veriler, bir CSV dosyasından yüklenmekte ve eksik değerler temizlenmektedir. Bu adım, güvenlik duvarının eğitiminde kullanılacak verilerin hazırlanmasını sağlar.

- **Makine öğrenimi modeli**: Proje, TfidfVectorizer ve LogisticRegression algoritmalarını kullanarak bir sınıflandırma modeli oluşturmaktadır. TfidfVectorizer, metin verilerini sayısal vektörlere dönüştürmek için kullanılan bir özellik çıkarma tekniğidir. LogisticRegression ise sınıflandırma algoritmasıdır. Bu model, web isteklerinin içerdiği metin verilerini analiz ederek saldırı türlerini tahmin etmektedir. Model, eğitim veri seti üzerinde eğitilir ve daha sonra gerçek zamanlı saldırıları tespit etmek için kullanılır.

- **Performans değerlendirmesi**: Oluşturulan modelin performansı, doğruluk, hassasiyet, geri çağırma ve F1 puanı gibi metrikler kullanılarak değerlendirilmektedir. Bu değerlendirme, modelin ne kadar iyi çalıştığını anlamak ve iyileştirmeler yapmak için önemlidir. Modelin doğruluğu ve etkinliği, gerçek saldırı türlerini doğru bir şekilde tespit etme yeteneğiyle ölçülmektedir.

- **Paket yakalama ve engelleme**: Proje, scapy kütüphanesi aracılığıyla ağ trafiğini dinlemekte ve gelen paketleri analiz etmektedir. Bu adım, web uygulamasına yönelik gelen istekleri ve yanıtları yakalar. Yakalanan paketler, daha sonra analiz için işlenir ve saldırı türlerini tespit etmek için kullanılır. Belirli saldırı türleri tespit edildiğinde, proje ilgili IP adreslerini engelleyerek saldırıları önlemektedir.

- **Kural tabanlı koruma**: Proje, bir kural dosyasını okuyarak saldırı türleri ve koruma önlemleri arasındaki ilişkiyi anlamaktadır. Bu şekilde, belirli bir saldırı türü tespit edildiğinde ilgili koruma önlemleri uygulanabilir. Örneğin, SQL enjeksiyonu tespit edildiğinde, proje ilgili IP adresini engelleyebilir veya gerekli önlemleri alabilir.

## GEREKLİLİKLER:

- Python 3.9 veya daha yeni bir sürümünün yüklü olması gerekmektedir.
- Debian tabanlı Linux sistemler tavsiye edilmektedir.
- Aşağıda belirtilen kütüphanelerin projede kullanılması gerekmektedir:
    - **Pandas**: Veri manipülasyonu için kullanılan bir kütüphane.
    - **Scikit-learn**: Makine öğrenmesi modellerinin oluşturulması ve değerlendirilmesi için kullanılan bir kütüphane.
    - **Joblib**: Eğitilen makine öğrenmesi modellerinin kaydedilmesi ve yüklenmesi için kullanılan bir kütüphane.
    - **TfidfVectorizer**: Metin verilerinin sayısal özelliklere dönüştürülmesi için kullanılan bir kütüphane.
    - **Scapy**: Ağ paketlerini yakalamak ve manipüle etmek için kullanılan bir kütüphane.

Projeyi çalıştırmak için, yukarıda belirtilen kütüphanelerin Python ortamınızda yüklü olması gerekmektedir. Bunları pip veya conda gibi paket yöneticileri kullanarak kurabilirsiniz. Ayrıca, projenin düzgün çalışması için Python 3.9 veya daha yeni bir sürümünü kullanmanız tavsiye edilmektedir. Debian tabanlı Linux sistemler, projenin test edildiği ve tavsiye edilen işletim sistemleridir, ancak diğer Linux dağıtımlarında da çalışabilir.

Bu gereklilikleri karşıladığınızda, projeyi başarıyla çalıştırabilir ve geliştirme sürecine devam edebilirsiniz.

## ÖRNEK KULLANIM:
Projenin örnek kullanımı aşağıdaki adımları içerebilir:

- Veri seti hazırlanır ve eğitim için kullanılır.
- Eğitim veri seti üzerinde bir makine öğrenimi modeli oluşturulur.
- Proje başlatılır ve ağ trafiği dinlenmeye başlar.
- Gelen paketler analiz edilir ve potansiyel saldırılar tespit edilir.
- Saldırı türlerine bağlı olarak koruma önlemleri uygulanır.
- Saldırı tespitleri ve uygulanan koruma önlemleri bir log dosyasına kaydedilir.
- Proje, güncel saldırı türleri ve koruma önlemleri hakkında bildirimler gönderebilir.

## KORUMA VERİLEN SALDIRI TÜRLERİ

Projenin amacı, bir Web Uygulama Güvenlik Duvarı (WAF) oluşturmak ve belirli saldırı türlerine karşı koruma sağlamaktır. Aşağıda, projede hedeflenen saldırı türleri ve alınan koruma önlemleri bulunmaktadır:

- **SQL Enjeksiyonu (SQL Injection)**:
    SQL enjeksiyon saldırılarına karşı önlem alınmaktadır.
    Potansiyel SQL enjeksiyonları tespit edilerek engellenmektedir.

- **XSS Saldırıları (Cross-Site Scripting)**:
    XSS saldırılarına karşı koruma sağlanmaktadır.
    Zararlı JavaScript kodlarının enjekte edilmesi önlenmektedir.

- **Komut Enjeksiyonu (Command Injection)**:
    Komut enjeksiyonu saldırılarına karşı koruma mekanizmaları bulunmaktadır.
    Zararlı komutların enjekte edilmesi engellenmektedir.

- **Yol Geçişi (Path Traversal)**:
    Yol geçişi saldırılarına karşı önlem alınmaktadır.
    Erişim kontrolü ve kısıtlamalar ile zararlı dosya veya dizinlere erişim engellenmektedir.

- **JS İsteği (JS Injection)**:
    JS isteği saldırılarına karşı koruma sağlanmaktadır.
    Zararlı JavaScript kodlarının kullanılması engellenmektedir.

- **Yasaklı Kelimeler (Ban Word)**:
    Belirli yasaklı kelimelerin içeren istekler engellenmektedir.
    Saldırgan içerikli verilerin filtrelenmesi ve engellenmesi gerçekleştirilmektedir.

- **Dağıtılmış Hizmet Engelleme (DoS)**:
    DoS saldırılarına karşı koruma mekanizmaları bulunmaktadır.
    Belirli bir süre içinde gelen yoğun istekleri tespit ederek saldırıları engellenmektedir.

Bu saldırı türlerine karşı alınan koruma önlemleri, projenin temel amacı olan web uygulamalarını güvenli hale getirme çabasını yansıtmaktadır. Saldırıların tespit edilmesi ve engellenmesi, web uygulamalarının güvenliğini artırarak kullanıcı verilerini ve sistem bütünlüğünü korumayı hedeflemektedir.

## SONUÇ:
Bu proje, web uygulamalarını güvenlik tehditlerine karşı korumak için gelişmiş makine öğrenmesi tekniklerini kullanmaktadır. Bu sayede, potansiyel saldırıları tespit edebilir ve engelleyebilir. Bu proje, web uygulamalarının güvenliğini artırmak isteyen şirketler, geliştiriciler ve güvenlik uzmanları için faydalı bir araç olabilir.
