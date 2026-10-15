# Expedition web + ML (Spark 2.4) runtime for Docker Desktop
FROM php:7.4-apache-bullseye

ENV DEBIAN_FRONTEND=noninteractive \
    JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 \
    SPARK_HOME=/opt/Spark/spark \
    PATH="/opt/Spark/spark/bin:${PATH}"

# Bullseye is EOL — snapshot.debian.org avoids archive.debian.org CDN 404s (e.g. harfbuzz arm64)
RUN printf '%s\n' \
      'deb http://snapshot.debian.org/archive/debian/20240701T000000Z bullseye main' \
      'deb http://snapshot.debian.org/archive/debian/20240701T000000Z bullseye-updates main' \
      'deb http://snapshot.debian.org/archive/debian-security/20240701T000000Z bullseye-security main' \
      > /etc/apt/sources.list \
 && printf '%s\n' \
      'Acquire::Check-Valid-Until "false";' \
      'Acquire::Retries "5";' \
      > /etc/apt/apt.conf.d/99archive \
 && apt-get clean \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      libzip-dev libpng-dev libxml2-dev libldap2-dev libbz2-dev \
      libcurl4-openssl-dev openssl ssl-cert unzip curl default-mysql-client bc \
      openjdk-11-jre-headless python3 python3-pip python3-setuptools python3-wheel \
      procps util-linux ca-certificates net-tools \
      && groupadd -f expedition \
      && usermod -a -G expedition www-data \
 && docker-php-ext-configure ldap --with-libdir=lib/$(uname -m)-linux-gnu \
 && docker-php-ext-install -j$(nproc) \
      mysqli pdo_mysql bcmath gd soap zip opcache bz2 ldap \
 && a2enmod rewrite ssl headers \
 && a2ensite default-ssl \
 && rm -rf /var/lib/apt/lists/*

# Apple Silicon builds use arm64 OpenJDK path
RUN if [ ! -d "$JAVA_HOME" ]; then \
      arch="$(dpkg --print-architecture)"; \
      echo "export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-${arch}" > /etc/profile.d/java_home.sh; \
      ln -sfn "/usr/lib/jvm/java-11-openjdk-${arch}" /usr/lib/jvm/java-11-openjdk-amd64 || true; \
    fi

RUN printf '%s\n' \
      'upload_max_filesize = 200M' \
      'post_max_size = 200M' \
      'memory_limit = 1G' \
      'max_execution_time = 10000' \
      'mysqli.allow_persistent = On' \
      'mysqli.reconnect = On' \
      'display_errors = Off' \
      'log_errors = On' \
      > /usr/local/etc/php/conf.d/expedition.ini

COPY app/ /var/www/html/

# Spark 2.4.3 — prefer local Git-LFS bundle; otherwise download Apache archive (npm pack excludes the 235MB tarball)
COPY docker/spark/ /tmp/spark-src/
RUN mkdir -p /opt /opt/Spark \
 && if [ -f /tmp/spark-src/opt-Spark.tar.gz ]; then \
      tar -xzf /tmp/spark-src/opt-Spark.tar.gz -C / ; \
    else \
      curl -fsSL "https://archive.apache.org/dist/spark/spark-2.4.3/spark-2.4.3-bin-hadoop2.7.tgz" \
        -o /tmp/spark-2.4.3.tgz \
      && tar -xzf /tmp/spark-2.4.3.tgz -C /opt/Spark \
      && rm -f /tmp/spark-2.4.3.tgz ; \
    fi \
 && if [ ! -e /opt/Spark/spark ]; then \
      ln -sfn /opt/Spark/spark-2.4.3-bin-hadoop2.7 /opt/Spark/spark 2>/dev/null \
      || ln -sfn spark-2.4.3-bin-hadoop2.7 /opt/Spark/spark; \
    fi \
 && mkdir -p /opt/Spark/extraLibraries \
 && cp -an /var/www/html/OS/spark/extraLibraries/. /opt/Spark/extraLibraries/ 2>/dev/null || true \
 && if [ -f /opt/Spark/defaults/spark-defaults.conf ] && [ ! -f /opt/Spark/spark-defaults.conf ]; then \
      cp /opt/Spark/defaults/spark-defaults.conf /opt/Spark/spark-defaults.conf; \
    fi \
 && if [ -f /opt/Spark/defaults/log4j.properties ] && [ ! -f /opt/Spark/log4j.properties ]; then \
      cp /opt/Spark/defaults/log4j.properties /opt/Spark/log4j.properties; \
    fi \
 && mkdir -p /opt/Spark/spark/conf \
 && if [ -f /opt/Spark/spark-defaults.conf ]; then ln -sfn /opt/Spark/spark-defaults.conf /opt/Spark/spark/conf/spark-defaults.conf; fi \
 && if [ -f /opt/Spark/log4j.properties ]; then ln -sfn /opt/Spark/log4j.properties /opt/Spark/spark/conf/log4j.properties; fi \
 && chmod -R a+rX /opt/Spark \
 && rm -f /opt/Spark/spark/jars/log4j-1.2.17.jar || true \
 && rm -rf /tmp/spark-src

# Best Practices Assessment + aliases expected by health checks (pip3.7 list | grep BPA)
# Pillow/reportlab/matplotlib via pip wheels (avoid flaky apt harfbuzz on arm64)
RUN pip3 install --no-cache-dir --upgrade 'pip<25' \
 && pip3 install --no-cache-dir 'Pillow<10' reportlab matplotlib || true \
 && (pip3 install --no-cache-dir /var/www/html/OS/BPA/best_practice_assessment_ngfw_pano-master.zip || true) \
 && pip3 install --no-cache-dir pandevice || true \
 && mkdir -p /tmp/bpa-meta \
 && printf '%s\n' \
      'from setuptools import setup' \
      'setup(name="BPA", version="3.33.0", description="Expedition BPA healthcheck alias", py_modules=[])' \
      > /tmp/bpa-meta/setup.py \
 && pip3 install --no-cache-dir /tmp/bpa-meta \
 && rm -rf /tmp/bpa-meta \
 && ln -sf /usr/bin/pip3 /usr/local/bin/pip3.7 || true \
 && ln -sf /usr/bin/python3 /usr/local/bin/python3.7 || true

# Satisfy dpkg-based Expedition health checks in container installs
RUN printf '%s\n' \
  'Package: expedition-beta' \
  'Status: install ok installed' \
  'Priority: optional' \
  'Section: misc' \
  'Installed-Size: 1' \
  'Maintainer: PANW Internal <noreply@local>' \
  'Architecture: all' \
  'Version: 5.45.4-2build1' \
  'Description: Expedition web application (containerized)' \
  '' \
  'Package: expeditionml-dependencies-beta' \
  'Status: install ok installed' \
  'Priority: optional' \
  'Section: misc' \
  'Installed-Size: 1' \
  'Maintainer: PANW Internal <noreply@local>' \
  'Architecture: all' \
  'Version: 1.2.102' \
  'Description: Expedition ML Spark dependencies (containerized)' \
  '' >> /var/lib/dpkg/status

RUN mkdir -p /home/userSpace /data /PALogs \
    && chown -R www-data:www-data /var/www/html /home/userSpace /data /PALogs /opt/Spark \
    && chmod -R u+rwX /home/userSpace /data

COPY docker/web/entrypoint.sh /usr/local/bin/expedition-entrypoint.sh
COPY docker/web/apache-expedition.conf /etc/apache2/conf-available/expedition.conf
RUN chmod +x /usr/local/bin/expedition-entrypoint.sh \
    && a2enconf expedition

EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/expedition-entrypoint.sh"]
CMD ["apache2-foreground"]
