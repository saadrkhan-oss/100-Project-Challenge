FROM httpd:2.4

RUN sed -i 's/^#LoadModule include_module/LoadModule include_module/' \
        /usr/local/apache2/conf/httpd.conf && \
    sed -i 's/^    Options Indexes FollowSymLinks/    Options Indexes FollowSymLinks IncludesNOEXEC/' \
        /usr/local/apache2/conf/httpd.conf && \
    echo 'AddType text/html .shtml' >> /usr/local/apache2/conf/httpd.conf && \
    echo 'AddOutputFilter INCLUDES .shtml .html .htm' >> /usr/local/apache2/conf/httpd.conf && \
    echo 'XBitHack on' >> /usr/local/apache2/conf/httpd.conf
