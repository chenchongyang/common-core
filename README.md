# common-core

1. 秘钥管理工具
2. 提供标准的加密算法

## 组成
rootKey 管理 workKey

rootkey由三段式组成，代码中定义2段，环境变量定义第3段，
3段root经过'|'运算后得到第一个byte
该byte使用PDKF2+盐值迭代运算后，得到rootKey
