FROM apify/actor-node:20
COPY package*.json ./
RUN npm --quiet set progress=false && npm install --omit=dev --omit=optional --no-audit && echo "Installed"
COPY . ./
CMD npm start --silent
