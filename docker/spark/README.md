# Spark runtime bundle

`opt-Spark.tar.gz` is stored in **Git LFS** for local/Docker Desktop builds.

It is **excluded from the npm package** (GitHub Packages 256 MB limit). When the archive is missing, the web image Dockerfile downloads Apache Spark **2.4.3** during `docker build`.

To force the offline bundle:

```bash
git lfs pull
# ensure docker/spark/opt-Spark.tar.gz exists, then:
expedition build
```
