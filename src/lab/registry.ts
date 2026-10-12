import type { Exercise } from "./types";
import { exercise as xssReflected } from "../exercises/xss-reflected";
import { exercise as xssStored } from "../exercises/xss-stored";
import { exercise as xssDom } from "../exercises/xss-dom";
import { exercise as sqli } from "../exercises/sqli";
import { exercise as csrf } from "../exercises/csrf";
import { exercise as clickjacking } from "../exercises/clickjacking";
import { exercise as sessionFixation } from "../exercises/session-fixation";
import { exercise as openRedirect } from "../exercises/open-redirect";
import { exercise as headerInjection } from "../exercises/header-injection";
import { exercise as mailInjection } from "../exercises/mail-injection";
import { exercise as pathTraversal } from "../exercises/path-traversal";
import { exercise as osCommandInjection } from "../exercises/os-command-injection";
import { exercise as passwordStorage } from "../exercises/password-storage";
import { exercise as bruteforce } from "../exercises/bruteforce";
import { exercise as authz } from "../exercises/authz";

/** 学習順。章ごとに並べて表示される */
export const exercises: Exercise[] = [
  xssReflected,
  xssStored,
  xssDom,
  sqli,
  csrf,
  clickjacking,
  sessionFixation,
  openRedirect,
  headerInjection,
  mailInjection,
  pathTraversal,
  osCommandInjection,
  passwordStorage,
  bruteforce,
  authz,
];

export function getExercise(id: string): Exercise | undefined {
  return exercises.find((e) => e.id === id);
}
