"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultConfig = exports.updateDependency = exports.extractPackageFile = void 0;
const extract_1 = require("./extract");
Object.defineProperty(exports, "extractPackageFile", { enumerable: true, get: function () { return extract_1.extractPackageFile; } });
const update_1 = require("./update");
Object.defineProperty(exports, "updateDependency", { enumerable: true, get: function () { return update_1.updateDependency; } });
exports.defaultConfig = {
    fileMatch: ['(^|/)download.yaml$'],
};
//# sourceMappingURL=index.js.map