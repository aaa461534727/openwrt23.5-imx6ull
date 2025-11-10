const minify = require( 'html-minifier' ).minify,
	uglify = require( 'uglify-js' ),
	cleancss = require('clean-css'),
	path = require( 'path' ),
	fs = require( 'fs' );

let mini_config = {};

function init_cfg() {
	mini_config = {
		path: __dirname,
		distPath: "dist",
		project: void(0),
		miniFiles: [],
		ignoreFiles: [
			"package.json",
			"package-lock.json",
			"node_modules",
			"minify.js"
		],
		mergeRules: void(0),
		putLog: true
	};
}

var styles = {
    'bold'          : ['\x1B[1m',  '\x1B[22m'],
    'italic'        : ['\x1B[3m',  '\x1B[23m'],
    'underline'     : ['\x1B[4m',  '\x1B[24m'],
    'inverse'       : ['\x1B[7m',  '\x1B[27m'],
    'strikethrough' : ['\x1B[9m',  '\x1B[29m'],
    'white'         : ['\x1B[37m', '\x1B[39m'],
    'grey'          : ['\x1B[90m', '\x1B[39m'],
    'black'         : ['\x1B[30m', '\x1B[39m'],
    'blue'          : ['\x1B[34m', '\x1B[39m'],
    'cyan'          : ['\x1B[36m', '\x1B[39m'],
    'green'         : ['\x1B[32m', '\x1B[39m'],
    'magenta'       : ['\x1B[35m', '\x1B[39m'],
    'red'           : ['\x1B[31m', '\x1B[39m'],
    'yellow'        : ['\x1B[33m', '\x1B[39m'],
    'whiteBG'       : ['\x1B[47m', '\x1B[49m'],
    'greyBG'        : ['\x1B[49;5;8m', '\x1B[49m'],
    'blackBG'       : ['\x1B[40m', '\x1B[49m'],
    'blueBG'        : ['\x1B[44m', '\x1B[49m'],
    'cyanBG'        : ['\x1B[46m', '\x1B[49m'],
    'greenBG'       : ['\x1B[42m', '\x1B[49m'],
    'magentaBG'     : ['\x1B[45m', '\x1B[49m'],
    'redBG'         : ['\x1B[41m', '\x1B[49m'],
    'yellowBG'      : ['\x1B[43m', '\x1B[49m']
}

let myCallback = function() { }, current, events, retry = 0;
function log (key, s) {
	return `${styles[key][0]} ${s} ${styles[key][1]}`;
}

let project_debug = false;
exports.uglify = parse_argv;

function merge_cfg(obj) {
	if (obj.ignoreFiles) {
		mini_config.ignoreFiles = mini_config.ignoreFiles.concat(obj.ignoreFiles);
		delete obj.ignoreFiles;
	}
	Object.assign(mini_config, obj);
	mini_config.ignoreFiles.push(mini_config.distPath);
	mini_config.distPath = path.resolve(mini_config.path, mini_config.distPath);
	mini_config.ignoreFiles = new RegExp("^\\.|^(" + mini_config.ignoreFiles.join("|").replace(/\./g, "\\.") + ")$");
	mini_config.miniFiles = new RegExp("^(" + mini_config.miniFiles.join("|").replace(/\./g, "\\.") + ")$");
}

function merge_rules() {
	if (!mini_config.mergeRules) return ;
	let rules = mini_config.mergeRules;
	let temp = [];
	if (rules instanceof Array) {
		temp = rules;
	} else if(typeof rules === "object") {
		temp = [rules];
	}
	let parse_tips = function(tips) {
		let str = "";
		for (let i in tips) {
			str += `\t${i}: ${tips[i]}\n`
		}
		return str;
	};

	mini_config.mergeRules = [];
	temp.forEach(function(rule) {
		if (typeof rule !== "object" || rule.files === undefined || !(rule.files instanceof Array)) throw "合并规则配置格式错误";
		let output, type = rule.type || "js";
		if (rule.output)
			output = path.resolve(mini_config.path, rule.output);
		else
			output = path.join(mini_config.distPath, "index-all." + type);
		
		fs.mkdirSync(path.dirname(output), {recursive: true});

		
		let add_comment = function(tips, msg) {
			return `/**\n${parse_tips(tips)}*/\n\n;${msg}`
		};

		if (type === "css") 
			add_comment = function(tips, msg) {
				return `/**\n${parse_tips(tips)}*/\n\n${msg}`
			};
		
		for (let index = 0, files = rule.files;index < files.length;index++) {
			let file = files[index];
			file = path.resolve(mini_config.path, file);
			if (!isCompile(file, "")) continue ;
			mini_config.mergeRules.push(file);
			readFile(file, function(content) {
				let comment = "";
				if (index !== 0) comment += "\n\n\n";
				comment += `${add_comment({FileName: path.basename(file)}, content)}`;
				fs.appendFileSync(output, comment);
			})
		}
	})
}

function parse_argv (cfg) {
	events = {};
	init_cfg();
	retry = 0;
	if (typeof cfg === "object") {
		merge_cfg(cfg);
		myCallback = mini_config.callback;
	} else {
		let argv = process.argv, index;
		if ((index = argv.indexOf("-c")) > -1) {
			read_cfg(path.resolve(__dirname, argv[index + 1]));
		}
		if ((index = argv.indexOf("-d")) > -1) {
			mini_config.path = argv[index + 1]
		}
		if ((index = argv.indexOf("-p")) > -1) {
			mini_config.project = argv[index + 1]
		}
		project_debug = !!~argv.indexOf("--project");
	}
	parse_project();
}

function read_cfg (cfg) {
	try {
		let content = fs.readFileSync(cfg, {encoding: "utf-8"});
		mini_config.ignoreFiles.push(path.basename(cfg));
		content = JSON.parse(content);
		merge_cfg(content);
	} catch(err) {
		throw err;
	}
}

function parse_project() {
	if (mini_config.project || !project_debug) {
		start();
	} else {
		let read_project = '', projects = [];
		if (mini_config.projects) {
			let i = 1;
			for (let p in mini_config.projects) {
				read_project += `${i++}. ${p}\t`
				projects.push(p);
			}
		}
		if (read_project != '') {
			read_project = `请选择要编译的项目，输入对应序号按下回车键: \n  0. Default\t${read_project}\n`
			select_project(log('cyan', read_project, projects));
		} else {
			start();
		}
	}
}

function select_project(quest, projects) {
	const readline = require('readline');
	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout
	});

	let select = function () {
		rl.question(quest, (answer) => {
			answer = answer.trim();
			if (/^\d+$/.test(answer)) {
				answer = parseInt(answer);
				if (answer <= projects.length) {
					rl.close();
					if (answer != 0) {
						mini_config.project = projects[answer - 1]
					}
					start();
				} else {
					select();
				}
			} else {
				select();
			}
		});
	}
	select();
}

function rmdir (dir, callback) {
	fs.readdir(dir, (err, files) => {
	    function next(index) {
	        if (index == files.length) return fs.rmdir(dir, callback)
	        let newPath = path.join(dir, files[index]);
	        fs.stat(newPath, (err, stat) => {
	            if (stat.isDirectory() ) {
	                rmdir(newPath, () => next(index+1))
	            } else {
	                fs.unlink(newPath, () => next(index+1))
	            }
	        })
	    }
	    next(0)
	})
}

function start () {
	project_process();
	current = Date.now();
	fs.exists(mini_config.distPath, function (exist) {
		if (exist) {
			rmdir(mini_config.distPath, (err) => {
				if (err) {
					if (retry ===2) {
						myCallback("error");
						throw err;
					}
					start();
					retry++;
					return ;
				}
				console.log(`[${log("grey", "Remove")+'] '+log("red", mini_config.distPath)}`);
				mkdir();
			})
		} else {
			mkdir();
		}
	})
}

let project_re = null, project_rerename = {};
function project_process() {
	if (mini_config.project) {
		let res = mini_config.projects[ mini_config.project ];
		if (res instanceof Array) {
			project_re = res;
		} else if (typeof res === "object") {
			if (res.re && res.re instanceof Array) project_re = res.re;
			if (res.rename && res.rename instanceof Array) {
				for (let name of res.rename) {
					if (typeof name === "object") {
						if (name.src && name.dest) {
							project_rerename[ path.resolve(mini_config.path, name.src) ] = name.dest;
						}
					}
				}
			}
		} else {
			throw "检查该项目是否存在或定义格式是否正确"
		}
		console.log(`\nThe UI-Project ${mini_config.project} in Compiling`);
	}
}

function get_dest_rename(src, dest) {
	if (project_rerename[src] != undefined) {
		return dest.replace(path.basename(dest), project_rerename[src]);
	}
	return dest;
}

function mkdir () {
	fs.mkdir(mini_config.distPath, function (err) {
		if (err) {
			myCallback("error");
			console.log(err);
			return;
		}
		console.log(`[${log("grey", "Create save") + '] ' + log("green", mini_config.distPath)}`);
		merge_rules();
		readdir(mini_config.path, mini_config.distPath);
	});
}

function readdir(_dir, _dist) {
	var files = fs.readdirSync(_dir);
	files.forEach(function(file, index) {
		var dirPath = path.join(_dir, file),
			destFile = path.join(_dist, file);
		if (!isCompile(dirPath, file)) return ;
		var stat = fs.lstatSync(dirPath);
		if (stat.isDirectory()) {
			fs.exists(destFile, function (exist) {
				if (!exist) {
					fs.mkdirSync(destFile);
				}
				readdir(dirPath, destFile);
			})
		} else {
			events[dirPath] = {fileSize: stat.size};
			readFile(dirPath, destFile);
		}
	});
}

function copyFile(src, dst, callback) {
	dst = get_dest_rename(src, dst);
	var readable = fs.createReadStream( src ),
		writable = fs.createWriteStream( dst ); 
	readable.pipe( writable );
	writable.once("close", function() {
		callback && callback();
	})
}

function isCompile (dirPath, file) {
	if ( mini_config.ignoreFiles.test(file) ) return false;
	if ( mini_config.miniFiles.test(file) ) return true;
	if (project_re) {
		let exist = false;
		for (let p of project_re) {
			if (regDir( path.resolve(mini_config.path, p) ).test(dirPath) || path.resolve(mini_config.path, p).indexOf(dirPath) > -1) {
				exist = true;
				break;
			}
		}
		return exist;
	}
	return true;
}

function data_parse(ext, content, callback, dir) {
	try {
		switch(ext) {
			case 'html':
			case 'htm':
			case 'asp':
				return callback(
					minify(content, {
						removeComments: true,
						collapseWhitespace: true,
						minifyJS: true,
						minifyCSS: true
					})
				)
			case 'js':
				return callback( uglify.minify(content).code );
			case 'css':
				return cleancss.process(content, {to: mini_config.distPath})
					.then(function(output){
						callback(output.css);
					})
			case 'json':
				return callback( JSON.stringify( JSON.parse(content) ) );
		}
	} catch(e) {
		console.log(log("red", `Path: ${dir}, Error: ${e.message}`));
		return callback(content);
	}
	return callback("");
}

let read_finsh = 0, read_finsh_mask = 0;
function readFile (dir, dest, callback) {
	if (dest instanceof Function) {
		callback = dest;
		dest = void(0);
	}
	if (dest && mini_config.mergeRules && !!~mini_config.mergeRules.indexOf(dir)) return ;
	let ext = path.extname(dir).replace('.', '');
	if (!!~("js,html,htm,asp,css,json".split(',').indexOf(ext)) && !~dir.indexOf(".min.")) {
		let content;
		try {
			content = fs.readFileSync(dir, "utf8");
			if (dest)
				events[dir].startTime = Date.now();
		} catch (e) {
			console.log("文件读取出错", dir);
			myCallback("error");
			throw e;
		} finally {
			data_parse(ext, content, function(_) {
				if (callback) {
					callback(_);
				} else {
					writeFile(dir, dest, _);
				}
			}, dir)
		}
	} else {
		copyFile(dir, dest);
	}
	read_finsh ++;
}

function writeFile (dir, resultdir, content) {
	resultdir = get_dest_rename(dir, resultdir);
	fs.writeFileSync(resultdir, content);
	if (events[dir]) {
		var diff = Date.now() - events[dir].startTime;
		var stat = fs.lstatSync(resultdir);
		mini_config.putLog && console.log(`[${log("grey", "Finished")}] ${log("cyan", path.basename(dir))} Size${log("green", unit(events[dir].fileSize) + ' --> ' + unit(stat.size))} After ~${log("magenta", diff / 1000+'s')}`);
	}
}

function unit (size) {
	return (size/1024).toFixed(2)+'KB'
}

if(!module.parent) {
	parse_argv();
} else {
	let inter = setInterval(function() {
		if (read_finsh_mask === read_finsh) {
			myCallback((Date.now() - current) / 1000 - 2);
			clearInterval(inter);
		}
		read_finsh_mask = read_finsh;
	}, 3000);
}
process.on('beforeExit', (code) => {
	console.log(`[ Process End ] Total use Time ${(Date.now() - current) / 1000} s`);
});

function regDir(str) {
    var reg = str
    if(typeof reg=="string") {
        reg = reg.replace(/[\[\]\\\^\:\.\?\+]/g, function(m) {
            return "\\"+m;
        })
        reg = reg.replace(/\*\*|\*/g, function(m) {
            if (m == "**") {
                return "[\\w\\W]*";
            } else {
                return "[^\\\/]*";
            }
        })
        reg = new RegExp(reg, "gi")
    }
    return reg
}