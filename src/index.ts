import fastifyCookie from "@fastify/cookie";
import fastifyFormbody from "@fastify/formbody";
import fastifyMultipart, { type MultipartFile } from "@fastify/multipart";
import fastifyStatic from "@fastify/static";
import { randomUUID } from "crypto";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import fs from "fs";
import path from "path";
import { pipeline } from "stream/promises";

if (!fs.existsSync("password.txt")) {
  fs.writeFileSync("password.txt", randomUUID());
}
const password = fs.readFileSync("./password.txt").toString();
if (!password)
  throw new Error(
    "Password not found! Put the password in the file named password.txt"
  );
const fastify = Fastify();

fastify.register(fastifyCookie, {
  secret: password,
  hook: "preHandler",
});
fastify.register(fastifyFormbody);
fastify.register(fastifyMultipart);
fastify.register(fastifyStatic, {
  root: path.resolve("files"),
  prefix: "/i/",
});
const auth = async (req: FastifyRequest, reply: FastifyReply) => {
  const pw = req.cookies.auth || (req.query as { password: string })?.password;
  if (pw !== process.env.ADMIN_PASSWORD) {
    return reply.code(401).send({ error: "Unauthorized" });
  }
};

fastify.route({
  method: "GET",
  url: "/",
  handler: async (req, reply) => {
    if (!req.cookies["password"])
      return reply
        .type("text/html")
        .send(fs.readFileSync("views/login.html", "utf-8"));
    return reply
      .type("text/html")
      .send(fs.readFileSync("views/index.html", "utf-8"));
  },
});
fastify.post<{
  Body: {
    password: string;
  };
}>("/login", async (req, reply) => {
  const givenPassword = req.body?.password;
  if (password !== givenPassword) return reply.code(401).send("Wrong password");
  reply.setCookie("password", password, {
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
  });
  reply.redirect("/");
});
const allowedMimeTypes = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "image/bmp",
  "image/apng",
  "audio/aac",
  "image/avif",
  "audio/mpeg",
  "video/mp4",
  "video/mpeg",
  "audio/ogg",
  "video/ogg",
  "audio/ogg",
  "font/otf",
  "text/plain",
  "audio/wav",
  "audio/webm",
  "video/webm",
  "image/webp",
  "font/woff",
  "font/woff2",
];
fastify.post("/upload", async (req: FastifyRequest, reply: FastifyReply) => {
  if (!req.cookies["password"])
    return reply.code(401).send({ error: "Not logged in" });
  if (req.cookies["password"] !== password)
    return reply.code(403).send({ error: "Invalid password" });
  let fileUploaded = false;

  const parts = req.parts({
    limits: {
      fileSize: 50 * 1024 * 1024,
    },
  });
  for await (const part of parts) {
    if (part.type === "file" && !fileUploaded) {
      const file: MultipartFile = part;
      if (!allowedMimeTypes.includes(file.mimetype)) {
        return reply
          .code(400)
          .send({ error: "This file type is not allowed!" });
      }
      const customFilename = (
        part.fields["customFilename"] as { value: string }
      )?.value;
      const _fileName = customFilename
        ? `${customFilename
            .split(".")
            .slice(0, customFilename.split(".").length - 1)}.${
            file.mimetype.split("/")[1]
          }`
        : file.filename;
      if (/[\/\x00]/.test(_fileName))
        return reply.code(400).send({ error: "Invalid file name!" });
      await pipeline(file.file, fs.createWriteStream(`files/${_fileName}`));
      fileUploaded = true;
      return reply.send({
        status: "File uploaded",
        fileName: _fileName,
      });
    }
  }

  if (!fileUploaded) {
    return reply
      .code(400)
      .send({ error: "Only one file is allowed, none uploaded" });
  }
});
fastify.listen({
  port: 3000,
});
