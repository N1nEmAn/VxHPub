# 一个给VxWorks固件分析的工具

ida_tools下的可以直接复制到ida下的对应插件文件夹直接使用。
fs_tools是用于提取minifs的。
提取以及段分析可以执行
```sh
cd ./ana_tools/ && ./install.sh
```
进行安装。
然后使用`vxana $firmware`即可解包分析等。
感谢长亭科技0x300战队队长郑吉宏提供了ida和minifs的工具基础脚本，其中ida的脚本我在其基础上进行了一些修改（本人获得授权）！
参考视频：https://www.bilibili.com/video/BV1D3411b7XY/?vd_source=6ebf6ec4787fcf8ce63c27bc330b3783
