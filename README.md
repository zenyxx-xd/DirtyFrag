# RootMyVivo DirtyFrag — свой форк DFRoot (diabl0w/DFRoot) с механизмом RootMyAndroid

Свой форк исходников DirtyFrag (CVE-2026-43284). ko-модули собираются
GitHub Actions (ddk-min контейнеры) и встраиваются в APK RootMyVivo как
экспортируемые символы `dirtyfrag_ko_*_start/_end`.

Изменения относительно оригинала:
- путь бутстрапа в lkm/dfroot.c → `/data/user_de/0/com.rootmyvivo/bootstrap` (наш пакет);
- KMI android14-6.1 удалён (примитив мёртв — accidental mitigation);
- userspace-часть (HMAC-SHA256 SA, /dev/df мьютекс, dfm0/dfm1, PACIASP/BTI, restore-порядок) живёт в RootMyVivo: `app/src/main/jni/`.
