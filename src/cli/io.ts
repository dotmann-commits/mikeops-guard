export interface CliIo {
  cwd: string;
  env: NodeJS.ProcessEnv;
  isTty: boolean;
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

export const processIo: CliIo = {
  cwd: process.cwd(),
  env: process.env,
  isTty: Boolean(process.stdout.isTTY),
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
};
