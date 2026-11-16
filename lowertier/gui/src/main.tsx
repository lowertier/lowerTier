import { render } from "solid-js/web";
import App from "./App";
import { hasKey } from "./api";
import { start } from "./store";
import "./style.css";
import "./theme";
import { appLayout } from "./native";
import DeviceApp from "./DeviceApp";
import "./device.css";

render(() => appLayout ? <DeviceApp /> : <App />, document.getElementById("app")!);
if (hasKey && !appLayout) start();
