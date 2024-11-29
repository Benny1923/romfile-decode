# romfile decode

decode romfile.cfg

如果你的路由器備份長這樣，可以試試看用這個解

```
hexdump -C romfile.cfg
00000000  c3 ad b0 b2 b9 b6 b3 ba  c1 df c3 a8 9e 91 c1 f5  |................|
00000010  f6 c3 bc 90 92 92 90 91  df ab 8d 9e 91 8c b2 90  |................|
...
```

## 用法

```sh
./romfile-decode romfile.cfg
```

然後他會產生 `romfile.json`

##  這可以幹嘛

- 找回路由器的wifi密碼
- 找回PPPOE的帳密
- 不想要從備份恢復，只是想看看一部分設定
- 其他(總之就是我沒有想到的)
