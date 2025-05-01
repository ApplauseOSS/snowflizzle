# Install go into wolfi for build
FROM cgr.dev/chainguard/wolfi-base AS base
RUN apk update && apk add ca-certificates-bundle build-base openssh git go-1.24~=1.24.1

FROM base AS dev
WORKDIR /code
COPY . .
RUN make build

FROM base AS prod
COPY --from=dev /code/bin/run bin/
COPY --from=dev /code/snowflizzle .
CMD ["bin/run"]
