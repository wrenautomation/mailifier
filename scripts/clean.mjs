#!/usr/bin/env node
/** Empty dist before a build, so a renamed or deleted output cannot survive into a publish. */
import { rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

rmSync(resolve(dirname(fileURLToPath(import.meta.url)), "../dist"), {
  recursive: true,
  force: true,
});
