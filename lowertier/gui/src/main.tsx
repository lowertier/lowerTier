import { render } from "solid-js/web";
import App from "./App";
import { hasKey } from "./api";
import { start } from "./store";
import "./style.css";

render(() => <App />, document.getElementById("app")!);
if (hasKey) start();
