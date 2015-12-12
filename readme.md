mysql-harness-plugin-firewall
===

MySQL Router用のプラグイン

## SQL-leved Firewall
```
MySQL Driver ---> MySQL Router[mysql-harness-plugin-firewall] --> MySQL
```

通常のWAFとは異なる，実際に実行されるSQLを監視することができるので，
以下のようなことができると思われます。

- Error-Based SQL Injectionの検知
- Nginx Naxsiのような学習によるホワイトリストベースのSQL Injection検知
- ワードベースのSQL Injection検知(disable_functionのようなもの)

