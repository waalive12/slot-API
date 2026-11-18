# 可控slot slots https://ptsloft.com/


# slot-API · PT Slot API 多厂商老虎机游戏聚合接口

**slot-API** 是一个面向游戏平台和开发者的 **Slot 游戏聚合 API（Slot Game Aggregator API）**。它把不同游戏厂商的接口统一成一套接入方式。平台对接一次，就能接入多个已适配厂商，不用为每家厂商重复开发一套业务接口。

> A unified Slot Game API for integrating multiple game providers through a single API.

## 项目特点

- **一次对接，多厂商接入**：业务系统调用统一接口，厂商之间的协议差异由各自的适配层处理。
- **支持两类对接方式**：原厂接口直连，以及基于已有协议分析的兼容适配。具体支持范围以各厂商的接口文档为准。
- **厂商与游戏配置分离**：厂商适配独立维护。后续扩展厂商时，平台侧不需要从头重做对接。
