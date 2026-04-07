/**
 * UniComp Secure Parser v5.0
 *
 * Security features:
 * - DoS protection (input length, symbol count, timeout limits)
 * - Deterministic parsing without regex where possible
 * - Strict validation of all inputs
 * - Proper escaping and quoting
 * - Multi-line file parsing with comments support
 *
 * New in v5.0:
 * - Explicit vectors: lc (Layer Colors), tr (Transforms), gs (Grid Styles)
 * - Bake function to collapse history into final d, lc, tr, gs
 */

// ============================================================================
// SECURITY LIMITS
// ============================================================================

export const SECURITY_LIMITS = {
  MAX_INPUT_LENGTH: 10000,
  MAX_SYMBOLS: 1000,
  MAX_PARAMS_PER_SYMBOL: 20,
  MIN_GRID_SIZE: 2,
  MAX_GRID_SIZE: 100,
  TIMEOUT_MS: 100,
  MAX_LINES: 500,
} as const;

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

// Delta operator for incremental transformations
export type DeltaOp = '=' | '+=' | '-=';

export interface DeltaAngleForce {
  op: DeltaOp;
  angle: number;
  force: number;
}

export interface DeltaNumber {
  op: DeltaOp;
  value: number;
}

export interface DeltaScale {
  op: DeltaOp;
  x: number;
  y: number;
  // For offset (move): store grid expansion info for proper undo
  expandLeft?: number;
  expandTop?: number;
}

/** Move Expand: grid expansion caused by move beyond grid boundary */
export interface MoveExpand {
  el: number; // expand left (columns added)
  et: number; // expand top (rows added)
}

/** Scale Expand: grid expansion caused by scale beyond grid boundary */
export interface ScaleExpand {
  sl: number; // scale expand left
  st: number; // scale expand top
}

// --- Vectors for baked representation ---

/** Layer Colors vector (lc) – all material parameters */
export interface LCVector {
  c?: string;               // symbol color
  b?: string;               // symbol border (compound: "width, H, S%, L%, alpha")
  bc?: string;              // layer background (compound: "H, S%, L%, alpha, radius")
  bb?: string;              // layer border (compound: "width, H, S%, L%, alpha")
}

/** Transforms vector (tr) – visual distortions */
export interface TRVector {
  f?: 'h' | 'v' | 'hv';     // flip
  r?: number;               // rotation degrees
  m?: string;               // inner margins (e.g. "10t 5r 10b 5l")
  st?: { angle: number; force: number }; // skew / trapezoid
  sp?: { angle: number; force: number }; // parallelogram / perspective
  w?: { angle: number; force: number };  // warp
}

/** Grid Styles vector (gs) */
export interface GSVector {
  gc?: string;              // grid background (compound: "H, S%, L%, alpha, radius")
  gb?: string;              // grid border (compound: "width, H, S%, L%, alpha")
}

// --- History step (as before, extended) ---
export interface HistoryStep {
  index: number;
  st?: DeltaAngleForce;
  sp?: DeltaAngleForce;
  w?: DeltaAngleForce;       // warp transform
  rotate?: DeltaNumber;
  scale?: DeltaScale;
  offset?: DeltaScale;
  d?: DeltaScale;           // bounds dimensions (w, h) in grid cells
  me?: MoveExpand;           // move expand
  se?: ScaleExpand;          // scale expand
  opacity?: DeltaNumber;
  colorGroup?: DeltaColor;   // All color params: c, b, bc, bb (as compound strings)
}

export interface DeltaColor {
  op: DeltaOp;
  c?: string;
  b?: string;
  bc?: string;
  bb?: string;
  // Legacy aliases (mapped on parse)
  color?: string;            // c
  symbolBorderWidth?: number; // part of b
  symbolBorderColor?: string;
  symbolBorderOpacity?: number;
  layerBackground?: string;   // bc
  layerBackgroundOpacity?: number;
  layerBorderRadius?: string;
  layerBorderWidth?: number;  // bb
  layerBorderColor?: string;
  layerBorderOpacity?: number;
  opacity?: number;
  // Legacy compat
  background?: string;
  backgroundOpacity?: number;
  borderRadius?: string;
  strokeColor?: string;
  strokeWidth?: number;
  strokeOpacity?: number;
}

export interface KeyframeStep extends HistoryStep {
  duration: number;
}

// --- SymbolSpec (extended with vectors) ---
export interface SymbolSpec {
  char: string;
  start: number;
  end: number;
  opacity?: number;
  // --- New vector fields (baked) ---
  lc?: LCVector;             // layer colors (c, b, bc, bb)
  tr?: TRVector;             // transforms (f, r, m, st, sp, w)
  // --- Individual params (used during editing, may be collapsed into vectors) ---
  color?: string;            // c
  background?: string;       // bc background part
  backgroundOpacity?: number;
  borderRadius?: string;
  rotate?: number;
  flip?: 'h' | 'v' | 'hv';
  fontFamily?: string;
  id?: string;
  className?: string;
  name?: string;
  scale?: { x: number; y: number };
  offset?: { x: number; y: number };
  bounds?: { w: number; h: number }; // d result
  sp?: { angle: number; force: number };
  st?: { angle: number; force: number };
  w?: { angle: number; force: number };  // warp transform
  margin?: { top: number; right: number; bottom: number; left: number };
  position?: { top: number; right: number; bottom: number; left: number };
  transition?: number;
  playstate?: number;
  refId?: string;
  refName?: string;
  refClass?: string;
  // --- History and keyframes ---
  history?: HistoryStep[];
  keyframes?: KeyframeStep[];
  // --- Border properties (symbol border, layer border) ---
  strokeWidth?: number;      // b width
  strokeColor?: string;      // b color
  strokeOpacity?: number;    // b opacity
  layerBorderWidth?: number; // bb width
  layerBorderColor?: string; // bb color
  layerBorderOpacity?: number; // bb opacity
}

export interface GridDimensions {
  width: number;
  height: number;
}

// --- UniCompSpec (extended with vectors) ---
export interface UniCompSpec {
  gridSize: number;
  gridWidth: number;
  gridHeight: number;
  symbols: SymbolSpec[];
  raw: string;
  encoding?: string;
  name?: string;
  id?: string;
  className?: string;
  // --- Grid style vectors (baked) ---
  gs?: GSVector;              // grid styles (gc, gb)
  // --- Individual grid params (editing) ---
  background?: string;        // gc background part
  backgroundOpacity?: number;
  borderRadius?: string;
  strokeColor?: string;       // gb color
  strokeWidth?: number;       // gb width
  strokeOpacity?: number;     // gb opacity
  opacity?: number;
}

export interface ParseError {
  message: string;
  position?: number;
  line?: number;
  column?: number;
  context?: string;
}

export type ParseResult =
  | { success: true; spec: UniCompSpec }
  | { success: false; error: ParseError };

export interface MultiLineParseResult {
  blocks: ParsedBlock[];
  totalLines: number;
  validCount: number;
  errorCount: number;
  errorLines: ErrorLine[];
}

export interface ParsedBlock {
  lineNumber: number;
  raw: string;
  result: ParseResult;
  name?: string;
}

export interface ErrorLine {
  lineNumber: number;
  column?: number;
  message: string;
  raw: string;
}

// ============================================================================
// SECURITY HELPERS
// ============================================================================

function isDigit(char: string): boolean {
  const code = char.charCodeAt(0);
  return code >= 48 && code <= 57;
}

function isLetter(char: string): boolean {
  const code = char.charCodeAt(0);
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function isWhitespace(char: string): boolean {
  const code = char.charCodeAt(0);
  return code === 32 || code === 9 || code === 10 || code === 13;
}

function isIdentifierChar(char: string): boolean {
  return isLetter(char) || char === '_' || isDigit(char);
}

function isIdentifierStartChar(char: string): boolean {
  return isLetter(char) || char === '_';
}

const SPECIAL_CHARS = new Set([
  '(', ')', '[', ']', '{', '}',
  ':', ';', ',', '-', '=',
  '"', "'", '`', '\\',
  '<', '>', '^', '№',
  '!', '?', '*', '×', '÷',
  '+', '_', '~', '/', '|',
  '&', '%', '$', ' '
]);

function needsQuoting(char: string): boolean {
  return isDigit(char) || SPECIAL_CHARS.has(char);
}

// ============================================================================
// TOKEN TYPES & TOKENIZER
// ============================================================================

enum TokenType {
  LPAREN = 'LPAREN',
  RPAREN = 'RPAREN',
  LBRACKET = 'LBRACKET',
  RBRACKET = 'RBRACKET',
  COLON = 'COLON',
  SEMICOLON = 'SEMICOLON',
  COMMA = 'COMMA',
  DASH = 'DASH',
  PLUS = 'PLUS',
  EQUALS = 'EQUALS',
  NUMBER = 'NUMBER',
  SYMBOL = 'SYMBOL',
  QUOTED_STRING = 'QUOTED_STRING',
  IDENTIFIER = 'IDENTIFIER',
  TIMES = 'TIMES',
  HASH_REF = 'HASH_REF',
  AT_REF = 'AT_REF',
  DOT_REF = 'DOT_REF',
  EOF = 'EOF',
  UNKNOWN = 'UNKNOWN',
}

interface Token {
  type: TokenType;
  value: string;
  position: number;
  line: number;
  column: number;
}

class SecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecurityError';
  }
}

class Tokenizer {
  private input: string;
  private position: number = 0;
  private line: number = 1;
  private column: number = 1;
  private tokens: Token[] = [];
  private startTime: number;
  private inGridSpec: boolean = false;

  constructor(input: string) {
    if (input.length > SECURITY_LIMITS.MAX_INPUT_LENGTH) {
      throw new SecurityError(`Input too long: ${input.length} chars (max: ${SECURITY_LIMITS.MAX_INPUT_LENGTH})`);
    }
    this.input = input;
    this.startTime = Date.now();
  }

  private checkTimeout(): void {
    if (Date.now() - this.startTime > SECURITY_LIMITS.TIMEOUT_MS) {
      throw new SecurityError('Parsing timeout exceeded');
    }
  }

  private currentChar(): string | null {
    return this.position < this.input.length ? this.input[this.position] : null;
  }

  private advance(): void {
    if (this.position < this.input.length) {
      if (this.input[this.position] === '\n') {
        this.line++;
        this.column = 1;
      } else {
        this.column++;
      }
      this.position++;
    }
  }

  private skipWhitespace(): void {
    while (this.currentChar() && isWhitespace(this.currentChar()!)) {
      this.advance();
    }
  }

  private readNumber(): Token {
    const startPos = this.position;
    const startLine = this.line;
    const startCol = this.column;
    let value = '';

    while (this.currentChar() && isDigit(this.currentChar()!)) {
      value += this.currentChar();
      this.advance();
    }

    if (this.currentChar() === '.') {
      value += this.currentChar();
      this.advance();
      while (this.currentChar() && isDigit(this.currentChar()!)) {
        value += this.currentChar();
        this.advance();
      }
    }

    return { type: TokenType.NUMBER, value, position: startPos, line: startLine, column: startCol };
  }

  private readQuotedString(quoteChar: string): Token {
    const startPos = this.position;
    const startLine = this.line;
    const startCol = this.column;
    let value = '';

    this.advance();

    while (this.currentChar() && this.currentChar() !== quoteChar) {
      if (this.currentChar() === '\\') {
        this.advance();
        const escaped = this.currentChar();
        if (escaped) {
          switch (escaped) {
            case 'n': value += '\n'; break;
            case 't': value += '\t'; break;
            case 'r': value += '\r'; break;
            default: value += escaped;
          }
          this.advance();
        }
      } else {
        value += this.currentChar();
        this.advance();
      }
    }

    if (this.currentChar() === quoteChar) {
      this.advance();
    } else {
      throw new Error(`Unclosed quote starting at line ${startLine}, column ${startCol}`);
    }

    return { type: TokenType.QUOTED_STRING, value, position: startPos, line: startLine, column: startCol };
  }

  private readIdentifier(): Token {
    const startPos = this.position;
    const startLine = this.line;
    const startCol = this.column;
    let value = '';

    if (this.currentChar() && isIdentifierStartChar(this.currentChar()!)) {
      value += this.currentChar();
      this.advance();
    }

    while (this.currentChar() && isIdentifierChar(this.currentChar()!)) {
      value += this.currentChar();
      this.advance();
    }

    return { type: TokenType.IDENTIFIER, value, position: startPos, line: startLine, column: startCol };
  }

  private readRefToken(prefix: string, tokenType: TokenType): Token {
    const startPos = this.position;
    const startLine = this.line;
    const startCol = this.column;
    this.advance(); // skip # or @ or .
    let value = '';
    while (this.currentChar() && isIdentifierChar(this.currentChar()!)) {
      value += this.currentChar();
      this.advance();
    }
    if (value.length === 0) {
      throw new Error(`Expected identifier after '${prefix}' at line ${startLine}, column ${startCol}`);
    }
    return { type: tokenType, value, position: startPos, line: startLine, column: startCol };
  }

  private readSymbol(): Token {
    const startPos = this.position;
    const startLine = this.line;
    const startCol = this.column;

    if (this.currentChar() === '\\') {
      this.advance();
      const escaped = this.currentChar();
      if (escaped) {
        this.advance();
        return { type: TokenType.SYMBOL, value: escaped, position: startPos, line: startLine, column: startCol };
      }
      throw new Error(`Invalid escape at end of input`);
    }

    const char = this.currentChar();
    if (char) {
      const code = char.charCodeAt(0);
      if (code >= 0xD800 && code <= 0xDBFF) {
        this.advance();
        const low = this.currentChar();
        if (low) {
          this.advance();
          return { type: TokenType.SYMBOL, value: char + low, position: startPos, line: startLine, column: startCol };
        }
      }

      this.advance();
      return { type: TokenType.SYMBOL, value: char, position: startPos, line: startLine, column: startCol };
    }

    throw new Error(`Unexpected character at position ${startPos}`);
  }

  tokenize(): Token[] {
    this.tokens = [];
    this.inGridSpec = false;

    while (this.position < this.input.length) {
      this.checkTimeout();
      this.skipWhitespace();

      if (this.position >= this.input.length) break;

      const char = this.currentChar()!;

      switch (char) {
        case '(':
          this.inGridSpec = true;
          this.tokens.push({ type: TokenType.LPAREN, value: '(', position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case ')':
          this.inGridSpec = false;
          this.tokens.push({ type: TokenType.RPAREN, value: ')', position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case '[':
          this.tokens.push({ type: TokenType.LBRACKET, value: '[', position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case ']':
          this.tokens.push({ type: TokenType.RBRACKET, value: ']', position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case ':':
          this.tokens.push({ type: TokenType.COLON, value: ':', position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case ';':
          this.tokens.push({ type: TokenType.SEMICOLON, value: ';', position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case ',':
          this.tokens.push({ type: TokenType.COMMA, value: ',', position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case '-':
          this.tokens.push({ type: TokenType.DASH, value: '-', position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case '+':
          this.tokens.push({ type: TokenType.PLUS, value: '+', position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case '×':
          this.tokens.push({ type: TokenType.TIMES, value: char, position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case 'x':
        case 'X':
          if (this.inGridSpec) {
            this.tokens.push({ type: TokenType.TIMES, value: char, position: this.position, line: this.line, column: this.column });
            this.advance();
          } else {
            this.tokens.push(this.readIdentifier());
          }
          break;
        case '=':
          this.tokens.push({ type: TokenType.EQUALS, value: '=', position: this.position, line: this.line, column: this.column });
          this.advance();
          break;
        case '"':
        case "'":
        case '`':
          this.tokens.push(this.readQuotedString(char));
          break;
        case '#': {
          const nextPos = this.position + 1;
          if (nextPos < this.input.length && isIdentifierStartChar(this.input[nextPos])) {
            this.tokens.push(this.readRefToken('#', TokenType.HASH_REF));
          } else {
            this.tokens.push({ type: TokenType.UNKNOWN, value: char, position: this.position, line: this.line, column: this.column });
            this.advance();
          }
          break;
        }
        case '@': {
          const nextPos = this.position + 1;
          if (nextPos < this.input.length && isIdentifierStartChar(this.input[nextPos])) {
            this.tokens.push(this.readRefToken('@', TokenType.AT_REF));
          } else {
            this.tokens.push({ type: TokenType.UNKNOWN, value: char, position: this.position, line: this.line, column: this.column });
            this.advance();
          }
          break;
        }
        case '.': {
          const nextPos2 = this.position + 1;
          if (!this.inGridSpec && nextPos2 < this.input.length && isIdentifierStartChar(this.input[nextPos2])) {
            this.tokens.push(this.readRefToken('.', TokenType.DOT_REF));
          } else {
            this.tokens.push({ type: TokenType.UNKNOWN, value: char, position: this.position, line: this.line, column: this.column });
            this.advance();
          }
          break;
        }
        default:
          if (isDigit(char)) {
            this.tokens.push(this.readNumber());
          } else if (isIdentifierStartChar(char)) {
            this.tokens.push(this.readIdentifier());
          } else {
            if (SPECIAL_CHARS.has(char)) {
                this.tokens.push({ type: TokenType.UNKNOWN, value: char, position: this.position, line: this.line, column: this.column });
                this.advance();
            } else {
                this.tokens.push(this.readSymbol());
            }
          }
      }
    }

    this.tokens.push({ type: TokenType.EOF, value: '', position: this.position, line: this.line, column: this.column });
    return this.tokens;
  }
}

// ============================================================================
// COLOR VALIDATION
// ============================================================================

const VALID_COLORS = new Set([
  'red', 'green', 'blue', 'yellow', 'orange', 'purple', 'pink', 'cyan',
  'magenta', 'lime', 'teal', 'indigo', 'violet', 'brown', 'gray', 'grey',
  'black', 'white', 'gold', 'silver', 'coral', 'salmon', 'crimson',
  'navy', 'olive', 'maroon', 'aqua', 'fuchsia', 'tomato', 'plum'
]);

function isValidColor(value: string): boolean {
  if (VALID_COLORS.has(value.toLowerCase())) return true;
  if (value.startsWith('#')) {
    const hex = value.slice(1);
    if (hex.length !== 3 && hex.length !== 6 && hex.length !== 8) return false;
    for (let i = 0; i < hex.length; i++) {
      const code = hex.charCodeAt(i);
      const isHexDigit = isDigit(hex[i]) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102);
      if (!isHexDigit) return false;
    }
    return true;
  }
  // Support hsl(...) and hsla(...) formats
  if (/^hsla?\(\s*[\d.]+\s*,\s*[\d.]+%?\s*,\s*[\d.]+%?\s*(,\s*[\d.]+)?\s*\)$/.test(value)) return true;
  // Support rgb(...) and rgba(...) formats
  if (/^rgba?\(\s*[\d.]+\s*,\s*[\d.]+\s*,\s*[\d.]+\s*(,\s*[\d.]+)?\s*\)$/.test(value)) return true;
  // Support raw HSL: "H, S%, L%" (e.g. "161, 80%, 50%")
  if (/^\s*[\d.]+\s*,\s*[\d.]+%\s*,\s*[\d.]+%\s*$/.test(value)) return true;
  return false;
}

/** Parse raw HSL "H, S%, L%" to hsl() string, or return value as-is */
function normalizeColor(value: string): string {
  const m = value.match(/^\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*$/);
  if (m) return `hsl(${m[1]}, ${m[2]}%, ${m[3]}%)`;
  return value;
}

// ============================================================================
// BOX VALUE PARSER (for margin / position)
// ============================================================================

function parseBoxValue(value: string): { top: number; right: number; bottom: number; left: number } {
  const dirMap: Record<string, string> = { t: 'top', r: 'right', b: 'bottom', l: 'left' };
  const result = { top: 0, right: 0, bottom: 0, left: 0 };

  const dirParts = value.split(/\s+/);
  let usedDir = false;
  for (const part of dirParts) {
    const match = part.match(/^(-?\d*\.?\d+)(t|r|b|l)$/i);
    if (match) {
      const val = parseFloat(match[1]);
      const dir = match[2].toLowerCase();
      (result as any)[dirMap[dir]] = val;
      usedDir = true;
    }
  }

  if (!usedDir) {
    const nums = value.split(/\s+/).map(v => parseFloat(v)).filter(n => !isNaN(n));
    if (nums.length === 1) {
      result.top = result.right = result.bottom = result.left = nums[0];
    } else if (nums.length === 2) {
      result.top = result.bottom = nums[0];
      result.left = result.right = nums[1];
    } else if (nums.length === 3) {
      result.top = nums[0];
      result.left = result.right = nums[1];
      result.bottom = nums[2];
    } else if (nums.length >= 4) {
      result.top = nums[0];
      result.right = nums[1];
      result.bottom = nums[2];
      result.left = nums[3];
    }
  }

  return result;
}

function parseAngleForce(value: string, key: 'sp' | 'st' | 'w'): { angle: number; force: number } {
  const normalized = value
    .replace(/[–—]/g, '-')
    .replace(/,/g, ' ')
    .replace(/[°]/g, ' ')
    .trim();

  const values = normalized.match(/-?\d*\.?\d+/g)?.map(v => parseFloat(v)) ?? [];
  if (values.length < 2 || values.some(Number.isNaN)) {
    throw new Error(`Invalid ${key}: "${value}" (expected "angle force")`);
  }

  return {
    angle: values[0],
    force: Math.abs(values[1]),
  };
}

function parseAngleForceDelta(value: string): { angle: number; force: number } {
  const normalized = value
    .replace(/[–—]/g, '-')
    .replace(/,/g, ' ')
    .replace(/[°]/g, ' ')
    .trim();

  const values = normalized.match(/[+-]?\d*\.?\d+/g)?.map(v => parseFloat(v)) ?? [];
  if (values.length < 2 || values.some(Number.isNaN)) {
    throw new Error(`Invalid delta value: "${value}" (expected "angle,force")`);
  }

  return { angle: values[0], force: values[1] };
}

/**
 * Parse a compound color value into its components.
 * For example: "2, 30, 80%, 60%" -> { width: 2, h: 30, s: 80, l: 60, alpha: undefined }
 */
function parseCompoundColor(value: string, expectedParts: number): (number | undefined)[] {
  const parts = value.split(',').map(p => p.trim());
  const result: (number | undefined)[] = [];
  for (let i = 0; i < expectedParts; i++) {
    if (i < parts.length) {
      const num = parseFloat(parts[i].replace('%', ''));
      result.push(isNaN(num) ? undefined : num);
    } else {
      result.push(undefined);
    }
  }
  return result;
}

// ============================================================================
// PARSER ENGINE
// ============================================================================

class Parser {
  private tokens: Token[];
  private position: number = 0;
  private symbolCount: number = 0;
  private startTime: number;

  constructor(tokens: Token[]) {
    this.tokens = tokens;
    this.startTime = Date.now();
  }

  private checkTimeout(): void {
    if (Date.now() - this.startTime > SECURITY_LIMITS.TIMEOUT_MS) {
      throw new SecurityError('Parsing timeout exceeded');
    }
  }

  private checkSymbolLimit(): void {
    if (this.symbolCount > SECURITY_LIMITS.MAX_SYMBOLS) {
      throw new SecurityError(`Too many symbols: max ${SECURITY_LIMITS.MAX_SYMBOLS}`);
    }
  }

  private currentToken(): Token {
    return this.tokens[this.position];
  }

  private advance(): void {
    if (this.position < this.tokens.length - 1) {
      this.position++;
    }
  }

  private expect(type: TokenType): Token {
    const token = this.currentToken();
    if (token.type !== type) {
      throw new Error(
        `Expected ${type} but got ${token.type} "${token.value}" at line ${token.line}, column ${token.column}`
      );
    }
    const result = token;
    this.advance();
    return result;
  }

  private parseGridSpec(): GridDimensions {
    let width: number;
    let height: number;

    if (this.currentToken().type === TokenType.LPAREN) {
      this.advance();
      const firstNum = this.expect(TokenType.NUMBER);
      width = parseInt(firstNum.value, 10);

      if (this.currentToken().type === TokenType.TIMES) {
        this.advance();
        const secondNum = this.expect(TokenType.NUMBER);
        height = parseInt(secondNum.value, 10);
      } else {
        height = width;
      }

      this.expect(TokenType.RPAREN);
    } else {
      const numToken = this.expect(TokenType.NUMBER);
      width = parseInt(numToken.value, 10);
      height = width;
    }

    return { width, height };
  }

  private parseSymbolChar(): string {
    const token = this.currentToken();

    if (token.type === TokenType.SYMBOL) {
      this.advance();
      return token.value;
    } else if (token.type === TokenType.QUOTED_STRING) {
      this.advance();
      return token.value;
    } else if (token.type === TokenType.IDENTIFIER) {
      this.advance();
      const firstChar = token.value.charAt(0);

      if (token.value.length > 1) {
        const remaining = token.value.slice(1);
        let allDigits = true;
        for (let i = 0; i < remaining.length; i++) {
          if (!isDigit(remaining[i])) {
            allDigits = false;
            break;
          }
        }

        if (allDigits) {
          const numToken: Token = {
            type: TokenType.NUMBER,
            value: remaining,
            position: token.position + 1,
            line: token.line,
            column: token.column + 1,
          };
          this.tokens.splice(this.position, 0, numToken);
        } else {
          return token.value;
        }
      }

      return firstChar;
    } else {
      throw new Error(
        `Expected symbol but got ${token.type} "${token.value}" at line ${token.line}, column ${token.column}`
      );
    }
  }

  private parseIndexRange(): { start: number; end: number } {
    const startToken = this.expect(TokenType.NUMBER);
    
    const dashToken = this.currentToken();
    if (dashToken.type !== TokenType.DASH) {
      throw new Error(`Expected '-' after index but got ${dashToken.type} "${dashToken.value}" at line ${dashToken.line}, column ${dashToken.column}`);
    }
    this.advance();
    
    const nextToken = this.currentToken();
    if (nextToken.type !== TokenType.NUMBER) {
        throw new Error(
            `Expected number after '-' but got ${nextToken.type} "${nextToken.value}" at line ${nextToken.line}, column ${nextToken.column}. Invalid index range.`
        );
    }
    
    const endToken = this.expect(TokenType.NUMBER);

    return {
      start: parseInt(startToken.value, 10),
      end: parseInt(endToken.value, 10),
    };
  }

  private parseParameters(): Partial<SymbolSpec> {
    const params: Partial<SymbolSpec> = {};

    if (this.currentToken().type !== TokenType.LBRACKET) {
      return params;
    }

    this.advance();

    let paramCount = 0;

    while (this.currentToken().type !== TokenType.RBRACKET && this.currentToken().type !== TokenType.EOF) {
      paramCount++;
      if (paramCount > SECURITY_LIMITS.MAX_PARAMS_PER_SYMBOL) {
        throw new SecurityError(`Too many parameters: max ${SECURITY_LIMITS.MAX_PARAMS_PER_SYMBOL}`);
      }

      const curToken = this.currentToken();
      if (curToken.type === TokenType.HASH_REF) {
        params.refId = curToken.value;
        this.advance();
        if (this.currentToken().type === TokenType.SEMICOLON) this.advance();
        continue;
      }
      if (curToken.type === TokenType.AT_REF) {
        params.refName = curToken.value;
        this.advance();
        if (this.currentToken().type === TokenType.SEMICOLON) this.advance();
        continue;
      }
      if (curToken.type === TokenType.DOT_REF) {
        params.refClass = curToken.value;
        this.advance();
        if (this.currentToken().type === TokenType.SEMICOLON) this.advance();
        continue;
      }

      const keyToken = this.currentToken();
      if (keyToken.type !== TokenType.IDENTIFIER) {
        throw new Error(`Expected parameter key at line ${keyToken.line}, column ${keyToken.column}`);
      }
      this.advance();

      const key = keyToken.value.toLowerCase();
      this.expect(TokenType.EQUALS);

      // Read comma-separated numeric pairs via tokens (handles negative values correctly)
      if (key === 'o' || key === 'offset') {
        const { x, y } = this._readScalePair();
        params.offset = { x, y };
        if (this.currentToken().type === TokenType.SEMICOLON) this.advance();
        continue;
      }
      if (key === 's' || key === 'scale') {
        const { x, y } = this._readScalePair();
        params.scale = { x, y };
        if (this.currentToken().type === TokenType.SEMICOLON) this.advance();
        continue;
      }
      if (key === 'd' || key === 'bounds') {
        const { x, y } = this._readScalePair();
        params.bounds = { w: x, h: y };
        if (this.currentToken().type === TokenType.SEMICOLON) this.advance();
        continue;
      }

      if (key === 'sp' || key === 'st' || key=== 'w') {
        const valueTokens: Token[] = [];
        while (
          this.currentToken().type !== TokenType.SEMICOLON &&
          this.currentToken().type !== TokenType.RBRACKET &&
          this.currentToken().type !== TokenType.EOF
        ) {
          valueTokens.push(this.currentToken());
          this.advance();
        }

        const rawValue = valueTokens.map((t) => t.value).join(' ');
        const parsed = parseAngleForce(rawValue, key);
        if (key === 'sp') params.sp = parsed;
        else if (key === 'st') params.st = parsed;
        else params.w = parsed;

        if (this.currentToken().type === TokenType.SEMICOLON) {
          this.advance();
        }
        continue;
      }

      const valueToken = this.currentToken();

      let value: string;

      const colorKeys = ['c', 'b', 'bc', 'bb', 'gc', 'gb'];
      if (
        colorKeys.includes(key) &&
        valueToken.type === TokenType.IDENTIFIER &&
        /^(hsl|hsla|rgb|rgba)$/i.test(valueToken.value) &&
        this.position + 1 < this.tokens.length &&
        this.tokens[this.position + 1].type === TokenType.LPAREN
      ) {
        let funcStr = valueToken.value;
        this.advance();
        let depth = 0;
        while (this.currentToken().type !== TokenType.EOF) {
          const t = this.currentToken();
          if (t.type === TokenType.LPAREN) depth++;
          else if (t.type === TokenType.RPAREN) {
            depth--;
            if (depth === 0) {
              funcStr += t.value;
              this.advance();
              break;
            }
          }
          if (t.type === TokenType.COMMA) {
            funcStr += ', ';
          } else {
            funcStr += t.value;
          }
          this.advance();
        }
        value = funcStr;
      } else if (valueToken.type === TokenType.DASH) {
        this.advance();
        const numToken = this.currentToken();
        if (numToken.type === TokenType.NUMBER) {
          value = '-' + numToken.value;
          this.advance();
        } else {
          value = '-';
        }
      } else if (valueToken.type === TokenType.NUMBER) {
        value = valueToken.value;
        this.advance();
      } else if (valueToken.type === TokenType.SYMBOL) {
        value = valueToken.value;
        this.advance();
      } else if (valueToken.type === TokenType.QUOTED_STRING) {
        value = valueToken.value;
        this.advance();
      } else if (valueToken.type === TokenType.IDENTIFIER) {
        value = valueToken.value;
        this.advance();
      } else {
        throw new Error(
          `Expected parameter value at line ${valueToken.line}, column ${valueToken.column}`
        );
      }

      switch (key) {
        case 'c':
        case 'color':
          if (!isValidColor(value)) {
            throw new Error(`Invalid color: "${value}"`);
          }
          params.color = normalizeColor(value);
          break;
        case 'r':
        case 'rotate': {
          const rotate = parseFloat(value);
          if (isNaN(rotate)) {
            throw new Error(`Invalid rotation: "${value}" (must be a number)`);
          }
          params.rotate = ((rotate % 360) + 360) % 360;
          break;
        }
        case 'f':
        case 'flip':
          if (value !== 'h' && value !== 'v' && value !== 'hv') {
            throw new Error(`Invalid flip: "${value}" (must be h, v, or hv)`);
          }
          params.flip = value;
          break;
        case 'font':
        case 'fontfamily':
          params.fontFamily = value;
          break;
        case 'n':
        case 'name':
          params.name = value;
          break;
        case 'id':
          params.id = value;
          break;
        case 'class':
        case 'classname':
          params.className = value;
          break;
        case 's':
        case 'scale': {
          const parts = value.split(',').map(v => v.trim());
          const sx = parseFloat(parts[0]);
          const sy = parts.length > 1 ? parseFloat(parts[1]) : sx;
          if (isNaN(sx) || isNaN(sy) || sx <= 0 || sy <= 0) {
            throw new Error(`Invalid scale: "${value}" (must be positive numbers)`);
          }
          params.scale = { x: sx, y: sy };
          break;
        }
        case 't':
        case 'transition': {
          const t = parseFloat(value);
          if (isNaN(t) || t < 0) {
            throw new Error(`Invalid transition: "${value}" (must be >= 0)`);
          }
          params.transition = t;
          break;
        }
        case 'm':
        case 'margin': {
          params.margin = parseBoxValue(value);
          break;
        }
        case 'p':
        case 'playstate': {
          params.playstate = parseFloat(value);
          break;
        }
        case 'o':
        case 'offset': {
          const parts = value.split(',').map(v => v.trim());
          const ox = parseFloat(parts[0]);
          const oy = parts.length > 1 ? parseFloat(parts[1]) : ox;
          if (!isNaN(ox) && !isNaN(oy)) {
            params.offset = { x: ox, y: oy };
          }
          break;
        }
        case 'b': {
          // Symbol border: "width, H, S%, L%, alpha" (compound)
          const bMatch = value.match(/^\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*(?:,\s*([\d.]+))?\s*$/);
          if (bMatch) {
            params.strokeWidth = parseFloat(bMatch[1]);
            params.strokeColor = `hsl(${bMatch[2]}, ${bMatch[3]}%, ${bMatch[4]}%)`;
            if (bMatch[5]) params.strokeOpacity = parseFloat(bMatch[5]);
          } else {
            // Legacy: b= as background color
            if (isValidColor(value)) {
              params.background = normalizeColor(value);
            }
          }
          break;
        }
        case 'bc': {
          // Layer background: "H, S%, L%, alpha, radius" (compound)
          const bcCompound = value.match(/^\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*(?:,\s*([\d.]+))?\s*(?:,\s*(.+))?\s*$/);
          if (bcCompound) {
            params.background = `hsl(${bcCompound[1]}, ${bcCompound[2]}%, ${bcCompound[3]}%)`;
            if (bcCompound[4]) params.backgroundOpacity = parseFloat(bcCompound[4]);
            if (bcCompound[5]) params.borderRadius = bcCompound[5].trim();
          } else {
            // Legacy: bc= as stroke color with "Wpx, H, S%, L%"
            const legacyBc = value.match(/^\s*([\d.]+)px\s*,\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*$/);
            if (legacyBc) {
              params.strokeWidth = parseFloat(legacyBc[1]);
              params.strokeColor = `hsl(${legacyBc[2]}, ${legacyBc[3]}%, ${legacyBc[4]}%)`;
            } else if (isValidColor(value)) {
              params.background = normalizeColor(value);
            }
          }
          break;
        }
        case 'bb': {
          // Layer border: "width, H, S%, L%, alpha"
          const bbMatch = value.match(/^\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*(?:,\s*([\d.]+))?\s*$/);
          if (bbMatch) {
            params.layerBorderWidth = parseFloat(bbMatch[1]);
            params.layerBorderColor = `hsl(${bbMatch[2]}, ${bbMatch[3]}%, ${bbMatch[4]}%)`;
            if (bbMatch[5]) params.layerBorderOpacity = parseFloat(bbMatch[5]);
          }
          break;
        }
        case 'gc': {
          // Grid background: "H, S%, L%, alpha, radius"
          const gcCompound = value.match(/^\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*(?:,\s*([\d.]+))?\s*(?:,\s*(.+))?\s*$/);
          if (gcCompound) {
            params.background = `hsl(${gcCompound[1]}, ${gcCompound[2]}%, ${gcCompound[3]}%)`;
            if (gcCompound[4]) params.backgroundOpacity = parseFloat(gcCompound[4]);
            if (gcCompound[5]) params.borderRadius = gcCompound[5].trim();
          } else if (isValidColor(value)) {
            params.background = normalizeColor(value);
          }
          break;
        }
        case 'gb': {
          // Grid border: "width, H, S%, L%, alpha"
          const gbMatch = value.match(/^\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*(?:,\s*([\d.]+))?\s*$/);
          if (gbMatch) {
            params.strokeWidth = parseFloat(gbMatch[1]);
            params.strokeColor = `hsl(${gbMatch[2]}, ${gbMatch[3]}%, ${gbMatch[4]}%)`;
            if (gbMatch[5]) params.strokeOpacity = parseFloat(gbMatch[5]);
          }
          break;
        }
        case 'background':
          if (isValidColor(value)) params.background = normalizeColor(value);
          break;
        case 'w':
        case 'warp': {
          const w = parseFloat(value);
          if (!isNaN(w) && w >= 0) params.strokeWidth = w;
          break;
        }
        case 'strokecolor': {
          params.strokeColor = normalizeColor(value);
          break;
        }
      }

      if (this.currentToken().type === TokenType.SEMICOLON) {
        this.advance();
      }
    }

    this.expect(TokenType.RBRACKET);
    return params;
  }

  private peekForStepBlock(): boolean {
    let pos = this.position;
    if (this.tokens[pos].type !== TokenType.LBRACKET) return false;
    pos++;
    while (pos < this.tokens.length && this.tokens[pos].type !== TokenType.RBRACKET) {
      if (this.tokens[pos].type === TokenType.IDENTIFIER) {
        const key = this.tokens[pos].value.toLowerCase();
        if ((key === 'h' || key === 'k') &&
            pos + 1 < this.tokens.length &&
            this.tokens[pos + 1].type === TokenType.EQUALS) {
          return true;
        }
      }
      pos++;
    }
    return false;
  }

  private parseStepBlocks(): { type: 'history' | 'keyframe'; steps: (HistoryStep | KeyframeStep)[]; baseParams: Partial<SymbolSpec> } {
    const steps: (HistoryStep | KeyframeStep)[] = [];
    let type: 'history' | 'keyframe' = 'history';
    const baseParams: Partial<SymbolSpec> = {};
    let hasAnyK = false;

    while (this.currentToken().type === TokenType.LBRACKET) {
      this.advance();

      const step: any = { index: 0 };
      let stepHasK = false;

      while (this.currentToken().type !== TokenType.RBRACKET && this.currentToken().type !== TokenType.EOF) {
        const keyToken = this.currentToken();
        if (keyToken.type !== TokenType.IDENTIFIER) {
          throw new Error(`Expected parameter key at line ${keyToken.line}, column ${keyToken.column}`);
        }
        this.advance();

        const key = keyToken.value.toLowerCase();

        let op: DeltaOp = '=';
        if (this.currentToken().type === TokenType.DASH &&
            this.position + 1 < this.tokens.length &&
            this.tokens[this.position + 1].type === TokenType.EQUALS) {
          op = '-=';
          this.advance();
        } else if (this.currentToken().type === TokenType.PLUS &&
                   this.position + 1 < this.tokens.length &&
                   this.tokens[this.position + 1].type === TokenType.EQUALS) {
          op = '+=';
          this.advance();
        }

        this.expect(TokenType.EQUALS);

        if (key === 'h') {
          step.index = this._readNum();
        } else if (key === 'k') {
          step.index = this._readNum();
          stepHasK = true;
          hasAnyK = true;
          type = 'keyframe';
        } else if (key === 't') {
          step.duration = this._readDuration();
        } else if (key === 'sp' || key === 'st' || key=== 'w') {
          const valueTokens: Token[] = [];
          while (
            this.currentToken().type !== TokenType.SEMICOLON &&
            this.currentToken().type !== TokenType.RBRACKET &&
            this.currentToken().type !== TokenType.EOF
          ) {
            valueTokens.push(this.currentToken());
            this.advance();
          }
          const rawValue = valueTokens.map(tk => tk.value).join('');
          const parsed = parseAngleForceDelta(rawValue);
          step[key] = { op, angle: parsed.angle, force: parsed.force };
        } else if (key === 'r' || key === 'rotate') {
          step.rotate = { op, value: this._readNum() };
        } else if (key === 's' || key === 'scale') {
          const { x, y } = this._readScalePair();
          step.scale = { op, x, y };
        } else if (key === 'o' || key === 'offset') {
          const { x, y } = this._readScalePair();
          step.offset = { op, x, y };
        } else if (key === 'me' || key === 'moveexpand') {
          const { x, y } = this._readScalePair();
          step.me = { el: x, et: y };
        } else if (key === 'el') {
          if (!step.me) step.me = { el: 0, et: 0 };
          step.me.el = this._readNum();
        } else if (key === 'et') {
          if (!step.me) step.me = { el: 0, et: 0 };
          step.me.et = this._readNum();
        } else if (key === 'se' || key === 'scaleexpand') {
          const { x, y } = this._readScalePair();
          step.se = { sl: x, st: y };
        } else if (key === 'sl') {
          if (!step.se) step.se = { sl: 0, st: 0 };
          step.se.sl = this._readNum();
        } else if (key === 'st') { // careful: 'st' is also used for skew, but in this context it's scale expand top
          if (!step.se) step.se = { sl: 0, st: 0 };
          step.se.st = this._readNum();
        } else if (key === 'd' || key === 'bounds') {
          const { x, y } = this._readScalePair();
          step.d = { op, x, y };
        } else if (key === 'c' || key === 'color') {
          const val = this._readColorValue();
          const normalized = normalizeColor(val);
          baseParams.color = normalized;
          if (!step.colorGroup) step.colorGroup = { op: '=' };
          step.colorGroup.c = normalized;
        } else if (key === 'b') {
          const val = this._readColorValue();
          // Try to parse as compound
          const bMatch = val.match(/^\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*(?:,\s*([\d.]+))?\s*$/);
          if (bMatch) {
            const sw = parseFloat(bMatch[1]);
            const sc = `hsl(${bMatch[2]}, ${bMatch[3]}%, ${bMatch[4]}%)`;
            baseParams.strokeWidth = sw;
            baseParams.strokeColor = sc;
            if (!step.colorGroup) step.colorGroup = { op: '=' };
            step.colorGroup.b = val; // store as original compound
            if (bMatch[5]) {
              baseParams.strokeOpacity = parseFloat(bMatch[5]);
            }
          } else {
            const normalized = normalizeColor(val);
            baseParams.background = normalized; // legacy
            if (!step.colorGroup) step.colorGroup = { op: '=' };
            step.colorGroup.b = val;
          }
        } else if (key === 'bc') {
          const val = this._readColorValue();
          const bcCompound = val.match(/^\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*(?:,\s*([\d.]+))?\s*(?:,\s*(.+))?\s*$/);
          if (bcCompound) {
            const bg = `hsl(${bcCompound[1]}, ${bcCompound[2]}%, ${bcCompound[3]}%)`;
            baseParams.background = bg;
            if (!step.colorGroup) step.colorGroup = { op: '=' };
            step.colorGroup.bc = val;
            if (bcCompound[4]) baseParams.backgroundOpacity = parseFloat(bcCompound[4]);
            if (bcCompound[5]) baseParams.borderRadius = bcCompound[5].trim();
          } else {
            // Legacy: bc= as stroke color with "Wpx, H, S%, L%"
            const legacyBc = val.match(/^\s*([\d.]+)px\s*,\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*$/);
            if (legacyBc) {
              baseParams.strokeWidth = parseFloat(legacyBc[1]);
              baseParams.strokeColor = `hsl(${legacyBc[2]}, ${legacyBc[3]}%, ${legacyBc[4]}%)`;
              if (!step.colorGroup) step.colorGroup = { op: '=' };
              step.colorGroup.bc = val;
            } else {
              const normalized = normalizeColor(val);
              baseParams.background = normalized;
              if (!step.colorGroup) step.colorGroup = { op: '=' };
              step.colorGroup.bc = val;
            }
          }
        } else if (key === 'bb') {
          const val = this._readColorValue();
          const bbMatch = val.match(/^\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*(?:,\s*([\d.]+))?\s*$/);
          if (bbMatch) {
            baseParams.layerBorderWidth = parseFloat(bbMatch[1]);
            baseParams.layerBorderColor = `hsl(${bbMatch[2]}, ${bbMatch[3]}%, ${bbMatch[4]}%)`;
            if (!step.colorGroup) step.colorGroup = { op: '=' };
            step.colorGroup.bb = val;
            if (bbMatch[5]) baseParams.layerBorderOpacity = parseFloat(bbMatch[5]);
          }
        } else if (key === 'background') {
          const val = this._readColorValue();
          const normalized = normalizeColor(val);
          baseParams.background = normalized;
          if (!step.colorGroup) step.colorGroup = { op: '=' };
          step.colorGroup.background = normalized;
        } else if (key === 'strokecolor') {
          const val = this._readColorValue();
          const normalized = normalizeColor(val);
          baseParams.strokeColor = normalized;
          if (!step.colorGroup) step.colorGroup = { op: '=' };
          step.colorGroup.strokeColor = normalized;
        } else if (key === 'bw' || key === 'strokewidth') {
          const bw = this._readNum();
          baseParams.strokeWidth = bw;
          if (!step.colorGroup) step.colorGroup = { op: '=' };
          step.colorGroup.strokeWidth = bw;
        } else if (key === 'bo' || key === 'strokeopacity') {
          const bo = this._readNum();
          baseParams.strokeOpacity = bo;
          if (!step.colorGroup) step.colorGroup = { op: '=' };
          step.colorGroup.strokeOpacity = bo;
        } else if (key === 'ba' || key === 'backgroundopacity') {
          const ba = this._readNum();
          baseParams.backgroundOpacity = ba;
          if (!step.colorGroup) step.colorGroup = { op: '=' };
          step.colorGroup.backgroundOpacity = ba;
        } else if (key === 'br' || key === 'borderradius') {
          let brVal: string;
          if (this.currentToken().type === TokenType.QUOTED_STRING) {
            brVal = this.currentToken().value.trim();
            this.advance();
          } else {
            let raw = '';
            while (this.currentToken().type !== TokenType.SEMICOLON &&
                   this.currentToken().type !== TokenType.RBRACKET &&
                   this.currentToken().type !== TokenType.EOF) {
              raw += this.currentToken().value;
              this.advance();
            }
            brVal = raw.trim();
          }
          baseParams.borderRadius = brVal;
          if (!step.colorGroup) step.colorGroup = { op: '=' };
          step.colorGroup.borderRadius = brVal;
        } else if (key === 'f' || key === 'flip') {
          if (this.currentToken().type === TokenType.QUOTED_STRING || this.currentToken().type === TokenType.IDENTIFIER) {
            baseParams.flip = this.currentToken().value as any;
            this.advance();
          }
        } else if (key === 'font') {
          if (this.currentToken().type === TokenType.QUOTED_STRING) {
            baseParams.fontFamily = this.currentToken().value;
            this.advance();
          } else {
            baseParams.fontFamily = this.currentToken().value;
            this.advance();
          }
        } else if (key === 'id') {
          baseParams.id = this.currentToken().type === TokenType.QUOTED_STRING ? this.currentToken().value : this.currentToken().value;
          this.advance();
        } else if (key === 'class') {
          baseParams.className = this.currentToken().type === TokenType.QUOTED_STRING ? this.currentToken().value : this.currentToken().value;
          this.advance();
        } else if (key === 'n' || key === 'name') {
          baseParams.name = this.currentToken().type === TokenType.QUOTED_STRING ? this.currentToken().value : this.currentToken().value;
          this.advance();
        } else {
          while (this.currentToken().type !== TokenType.SEMICOLON &&
                  this.currentToken().type !== TokenType.RBRACKET &&
                  this.currentToken().type !== TokenType.EOF) {
            this.advance();
          }
        }

        if (this.currentToken().type === TokenType.SEMICOLON) {
          this.advance();
        }
      }

      this.expect(TokenType.RBRACKET);

      if (step.colorGroup && step.opacity) {
        if (!step.colorGroup.opacity) step.colorGroup.opacity = step.opacity.value;
        step.opacity = undefined;
      }

      if (stepHasK && step.duration === undefined) {
        step.duration = 1;
      }

      steps.push(step);
    }

    if (hasAnyK && steps.length > 0 && !('duration' in steps[0])) {
      (steps[0] as any).duration = 0;
      type = 'keyframe';
    }

    if (hasAnyK) {
      let kIdx = 0;
      for (const step of steps) {
        if ((step as any).duration !== undefined) {
          (step as any).index = kIdx++;
        }
      }
    }

    return { type, steps, baseParams };
  }

  private _readNum(): number {
    let sign = 1;
    if (this.currentToken().type === TokenType.DASH) {
      sign = -1;
      this.advance();
    } else if (this.currentToken().type === TokenType.PLUS) {
      this.advance();
    }
    const token = this.expect(TokenType.NUMBER);
    return parseFloat(token.value) * sign;
  }

  private _readDuration(): number {
    const first = this.expect(TokenType.NUMBER);
    let val = first.value;
    if (this.currentToken().type === TokenType.COMMA) {
      this.advance();
      if (this.currentToken().type === TokenType.NUMBER) {
        val += '.' + this.currentToken().value;
        this.advance();
      }
    }
    return parseFloat(val);
  }

  private _readScalePair(): { x: number; y: number } {
    const x = this._readNum();
    let y = x;
    if (this.currentToken().type === TokenType.COMMA) {
      this.advance();
      y = this._readNum();
    }
    return { x, y };
  }

  private _readColorValue(): string {
    const token = this.currentToken();
    if (token.type === TokenType.QUOTED_STRING) {
      this.advance();
      return token.value;
    }
    if (token.type === TokenType.IDENTIFIER && /^(hsl|hsla|rgb|rgba)$/i.test(token.value) &&
        this.position + 1 < this.tokens.length && this.tokens[this.position + 1].type === TokenType.LPAREN) {
      let funcStr = token.value;
      this.advance();
      let depth = 0;
      while (this.currentToken().type !== TokenType.EOF) {
        const t = this.currentToken();
        if (t.type === TokenType.LPAREN) depth++;
        else if (t.type === TokenType.RPAREN) {
          depth--;
          if (depth === 0) { funcStr += t.value; this.advance(); break; }
        }
        if (t.type === TokenType.COMMA) funcStr += ', ';
        else funcStr += t.value;
        this.advance();
      }
      return funcStr;
    }
    let val = '';
    while (this.currentToken().type !== TokenType.SEMICOLON &&
           this.currentToken().type !== TokenType.RBRACKET &&
           this.currentToken().type !== TokenType.EOF) {
      val += this.currentToken().value;
      this.advance();
    }
    return val;
  }

  private parseSymbol(gridWidth: number, gridHeight: number): SymbolSpec {
    this.checkTimeout();
    this.checkSymbolLimit();
    this.symbolCount++;

    const token = this.currentToken();
    let char = '';
    let refId: string | undefined;
    let refName: string | undefined;
    let refClass: string | undefined;

    if (token.type === TokenType.HASH_REF) {
      refId = token.value;
      char = '#' + token.value;
      this.advance();
    } else if (token.type === TokenType.AT_REF) {
      refName = token.value;
      char = '@' + token.value;
      this.advance();
    } else if (token.type === TokenType.DOT_REF) {
      refClass = token.value;
      char = '.' + token.value;
      this.advance();
    } else {
      char = this.parseSymbolChar();
    }

    let params: Partial<SymbolSpec> = {};

    if (this.currentToken().type === TokenType.LBRACKET) {
      if (this.peekForStepBlock()) {
        const result = this.parseStepBlocks();
        Object.assign(params, result.baseParams);
        if (result.type === 'history') {
          params.history = result.steps as HistoryStep[];
          const resolved = resolveHistory(result.steps as HistoryStep[]);
          if (resolved.st) params.st = resolved.st;
          if (resolved.sp) params.sp = resolved.sp;
          if (resolved.w) params.w = resolved.w;
          if (resolved.rotate !== undefined) params.rotate = resolved.rotate;
          if (resolved.scale) params.scale = resolved.scale;
          if (resolved.offset) params.offset = resolved.offset;
          if (resolved.d) params.bounds = { w: resolved.d.x, h: resolved.d.y };
          if (resolved.me) params.offset = { x: (params.offset?.x ?? 0) + resolved.me.el, y: (params.offset?.y ?? 0) + resolved.me.et }; // approximate
          if (resolved.se) params.scale = { x: (params.scale?.x ?? 1) + resolved.se.sl, y: (params.scale?.y ?? 1) + resolved.se.st };
          if (resolved.colorGroup) {
            if (resolved.colorGroup.c) params.color = resolved.colorGroup.c;
            if (resolved.colorGroup.b) {
              // try to parse b compound into strokeWidth, strokeColor, strokeOpacity
              const bParts = resolved.colorGroup.b.split(',').map(p => p.trim());
              if (bParts.length >= 4) {
                params.strokeWidth = parseFloat(bParts[0]);
                params.strokeColor = `hsl(${bParts[1]}, ${bParts[2]}, ${bParts[3]})`;
                if (bParts[4]) params.strokeOpacity = parseFloat(bParts[4]);
              }
            }
            if (resolved.colorGroup.bc) {
              const bcParts = resolved.colorGroup.bc.split(',').map(p => p.trim());
              if (bcParts.length >= 3) {
                params.background = `hsl(${bcParts[0]}, ${bcParts[1]}, ${bcParts[2]})`;
                if (bcParts[3]) params.backgroundOpacity = parseFloat(bcParts[3]);
                if (bcParts[4]) params.borderRadius = bcParts[4];
              }
            }
            if (resolved.colorGroup.bb) {
              const bbParts = resolved.colorGroup.bb.split(',').map(p => p.trim());
              if (bbParts.length >= 4) {
                params.layerBorderWidth = parseFloat(bbParts[0]);
                params.layerBorderColor = `hsl(${bbParts[1]}, ${bbParts[2]}, ${bbParts[3]})`;
                if (bbParts[4]) params.layerBorderOpacity = parseFloat(bbParts[4]);
              }
            }
            if (resolved.colorGroup.opacity !== undefined) params.opacity = resolved.colorGroup.opacity;
          }
        } else {
          params.keyframes = result.steps as KeyframeStep[];
          const firstGroupSteps: HistoryStep[] = [];
          for (let i = 0; i < result.steps.length; i++) {
            if (i > 0 && 'duration' in result.steps[i]) break;
            firstGroupSteps.push(result.steps[i] as HistoryStep);
          }
          const resolved = resolveHistory(firstGroupSteps);
          if (resolved.st) params.st = resolved.st;
          if (resolved.sp) params.sp = resolved.sp;
          if (resolved.w) params.w = resolved.w;
          if (resolved.rotate !== undefined) params.rotate = resolved.rotate;
          if (resolved.scale) params.scale = resolved.scale;
          if (resolved.offset) params.offset = resolved.offset;
          if (resolved.d) params.bounds = { w: resolved.d.x, h: resolved.d.y };
          if (resolved.me) params.offset = { x: (params.offset?.x ?? 0) + resolved.me.el, y: (params.offset?.y ?? 0) + resolved.me.et };
          if (resolved.se) params.scale = { x: (params.scale?.x ?? 1) + resolved.se.sl, y: (params.scale?.y ?? 1) + resolved.se.st };
          if (resolved.colorGroup) {
            if (resolved.colorGroup.c) params.color = resolved.colorGroup.c;
            if (resolved.colorGroup.b) {
              const bParts = resolved.colorGroup.b.split(',').map(p => p.trim());
              if (bParts.length >= 4) {
                params.strokeWidth = parseFloat(bParts[0]);
                params.strokeColor = `hsl(${bParts[1]}, ${bParts[2]}, ${bParts[3]})`;
                if (bParts[4]) params.strokeOpacity = parseFloat(bParts[4]);
              }
            }
            if (resolved.colorGroup.bc) {
              const bcParts = resolved.colorGroup.bc.split(',').map(p => p.trim());
              if (bcParts.length >= 3) {
                params.background = `hsl(${bcParts[0]}, ${bcParts[1]}, ${bcParts[2]})`;
                if (bcParts[3]) params.backgroundOpacity = parseFloat(bcParts[3]);
                if (bcParts[4]) params.borderRadius = bcParts[4];
              }
            }
            if (resolved.colorGroup.bb) {
              const bbParts = resolved.colorGroup.bb.split(',').map(p => p.trim());
              if (bbParts.length >= 4) {
                params.layerBorderWidth = parseFloat(bbParts[0]);
                params.layerBorderColor = `hsl(${bbParts[1]}, ${bbParts[2]}, ${bbParts[3]})`;
                if (bbParts[4]) params.layerBorderOpacity = parseFloat(bbParts[4]);
              }
            }
            if (resolved.colorGroup.opacity !== undefined) params.opacity = resolved.colorGroup.opacity;
          }
        }
      } else {
        params = this.parseParameters();
      }
    }

    // Support flat params block AFTER step blocks (e.g. flip, fontFamily, color not in history)
    if (params.history && this.currentToken().type === TokenType.LBRACKET && !this.peekForStepBlock()) {
      const extraParams = this.parseParameters();
      Object.assign(params, extraParams);
    }

    if (refId) params.refId = refId;
    if (refName) params.refName = refName;
    if (refClass) params.refClass = refClass;

    if (this.currentToken().type === TokenType.COMMA) {
      this.advance();
    }

    const { start, end } = this.parseIndexRange();

    const maxIndex = gridWidth * gridHeight - 1;
    if (start > maxIndex || end > maxIndex || start < 0 || end < 0) {
      throw new Error(
        `Index out of bounds. Valid range for ${gridWidth}×${gridHeight} grid is 0-${maxIndex}`
      );
    }

    return { char, start, end, ...params } as SymbolSpec;
  }

  parse(): ParseResult {
    try {
      const grid = this.parseGridSpec();
      const { width: gridWidth, height: gridHeight } = grid;

      if (gridWidth < SECURITY_LIMITS.MIN_GRID_SIZE || gridWidth > SECURITY_LIMITS.MAX_GRID_SIZE) {
        throw new Error(`Grid width must be between ${SECURITY_LIMITS.MIN_GRID_SIZE} and ${SECURITY_LIMITS.MAX_GRID_SIZE}`);
      }
      if (gridHeight < SECURITY_LIMITS.MIN_GRID_SIZE || gridHeight > SECURITY_LIMITS.MAX_GRID_SIZE) {
        throw new Error(`Grid height must be between ${SECURITY_LIMITS.MIN_GRID_SIZE} and ${SECURITY_LIMITS.MAX_GRID_SIZE}`);
      }

      let gridId: string | undefined;
      let gridClassName: string | undefined;
      let gridName: string | undefined;
      let gridBackground: string | undefined;
      let gridBackgroundOpacity: number | undefined;
      let gridBorderRadius: string | undefined;
      let gridStrokeColor: string | undefined;
      let gridStrokeWidth: number | undefined;
      let gridStrokeOpacity: number | undefined;
      let gridOpacity: number | undefined;
      if (this.currentToken().type === TokenType.LBRACKET) {
        const gridParams = this.parseParameters();
        gridId = gridParams.id;
        gridClassName = gridParams.className;
        gridName = gridParams.name;
        gridBackground = gridParams.background;
        gridBackgroundOpacity = gridParams.backgroundOpacity;
        gridBorderRadius = gridParams.borderRadius;
        gridStrokeColor = gridParams.strokeColor;
        gridStrokeWidth = gridParams.strokeWidth;
        gridStrokeOpacity = gridParams.strokeOpacity;
        gridOpacity = gridParams.opacity;
      }

      this.expect(TokenType.COLON);

      const symbols: SymbolSpec[] = [];

      while (this.currentToken().type !== TokenType.EOF) {
        symbols.push(this.parseSymbol(gridWidth, gridHeight));

        if (this.currentToken().type === TokenType.SEMICOLON) {
          this.advance();
        } else if (this.currentToken().type !== TokenType.EOF) {
          const token = this.currentToken();
          throw new Error(`Unexpected token ${token.type} "${token.value}" at line ${token.line}, column ${token.column}. Expected semicolon or end of input.`);
        }
      }

      return {
        success: true,
        spec: {
          gridSize: gridWidth,
          gridWidth,
          gridHeight,
          symbols,
          raw: this.tokens
            .filter((t) => t.type !== TokenType.EOF)
            .map((t) => t.value)
            .join(''),
          id: gridId,
          className: gridClassName,
          name: gridName,
          background: gridBackground,
          backgroundOpacity: gridBackgroundOpacity,
          borderRadius: gridBorderRadius,
          strokeColor: gridStrokeColor,
          strokeWidth: gridStrokeWidth,
          strokeOpacity: gridStrokeOpacity,
          opacity: gridOpacity,
        },
      };
    } catch (e) {
      return {
        success: false,
        error: {
          message: e instanceof Error ? e.message : 'Unknown parse error',
          position: this.currentToken().position,
          line: this.currentToken().line,
          column: this.currentToken().column,
        },
      };
    }
  }
}

// ============================================================================
// RESOLVE HISTORY – accumulate deltas into final values
// ============================================================================

/**
 * Compute accumulated (resolved) values from history steps.
 * Applies deltas sequentially: = sets, += adds, -= subtracts.
 */
export function resolveHistory(steps: HistoryStep[]): {
  st?: { angle: number; force: number };
  sp?: { angle: number; force: number };
  w?: { angle: number; force: number };
  rotate?: number;
  scale?: { x: number; y: number };
  offset?: { x: number; y: number };
  d?: { x: number; y: number }; // bounds: x=w, y=h
  me?: MoveExpand;
  se?: ScaleExpand;
  colorGroup?: DeltaColor;
} {
  let st: { angle: number; force: number } | undefined;
  let sp: { angle: number; force: number } | undefined;
  let w: { angle: number; force: number } | undefined;
  let rotate: number | undefined;
  let scale: { x: number; y: number } | undefined;
  let offset: { x: number; y: number } | undefined;
  let d: { x: number; y: number } | undefined;
  let me: MoveExpand | undefined;
  let se: ScaleExpand | undefined;
  let colorGroup: DeltaColor | undefined;

  for (const step of steps) {
    if (step.st) {
      if (step.st.op === '=' || !st) {
        st = { angle: step.st.angle, force: step.st.force };
      } else if (step.st.op === '+=') {
        st = { angle: st.angle + step.st.angle, force: st.force + step.st.force };
      } else if (step.st.op === '-=') {
        st = { angle: st.angle - step.st.angle, force: st.force - step.st.force };
      }
    }
    if (step.sp) {
      if (step.sp.op === '=' || !sp) {
        sp = { angle: step.sp.angle, force: step.sp.force };
      } else if (step.sp.op === '+=') {
        sp = { angle: sp.angle + step.sp.angle, force: sp.force + step.sp.force };
      } else if (step.sp.op === '-=') {
        sp = { angle: sp.angle - step.sp.angle, force: sp.force - step.sp.force };
      }
    }
    if (step.w) {
      if (step.w.op === '=' || !w) {
        w = { angle: step.w.angle, force: step.w.force };
      } else if (step.w.op === '+=') {
        w = { angle: w.angle + step.w.angle, force: w.force + step.w.force };
      } else if (step.w.op === '-=') {
        w = { angle: w.angle - step.w.angle, force: w.force - step.w.force };
      }
    }
    if (step.rotate) {
      if (step.rotate.op === '=' || rotate === undefined) {
        rotate = step.rotate.value;
      } else if (step.rotate.op === '+=') {
        rotate = rotate + step.rotate.value;
      } else if (step.rotate.op === '-=') {
        rotate = rotate - step.rotate.value;
      }
    }
    if (step.scale) {
      if (step.scale.op === '=' || !scale) {
        scale = { x: step.scale.x, y: step.scale.y };
      } else if (step.scale.op === '+=') {
        scale = { x: (scale?.x ?? 1) + step.scale.x, y: (scale?.y ?? 1) + step.scale.y };
      } else if (step.scale.op === '-=') {
        scale = { x: (scale?.x ?? 1) - step.scale.x, y: (scale?.y ?? 1) - step.scale.y };
      }
    }
    if (step.offset) {
      if (step.offset.op === '=' || !offset) {
        offset = { x: step.offset.x, y: step.offset.y };
      } else if (step.offset.op === '+=') {
        offset = { x: (offset?.x ?? 0) + step.offset.x, y: (offset?.y ?? 0) + step.offset.y };
      } else if (step.offset.op === '-=') {
        offset = { x: (offset?.x ?? 0) - step.offset.x, y: (offset?.y ?? 0) - step.offset.y };
      }
    }
    if (step.d) {
      if (step.d.op === '=' || !d) {
        d = { x: step.d.x, y: step.d.y };
      } else if (step.d.op === '+=') {
        d = { x: (d?.x ?? 0) + step.d.x, y: (d?.y ?? 0) + step.d.y };
      } else if (step.d.op === '-=') {
        d = { x: (d?.x ?? 0) - step.d.x, y: (d?.y ?? 0) - step.d.y };
      }
    }
    if (step.me) {
      if (!me) me = { el: step.me.el, et: step.me.et };
      else { me = { el: me.el + step.me.el, et: me.et + step.me.et }; }
    }
    if (step.se) {
      if (!se) se = { sl: step.se.sl, st: step.se.st };
      else { se = { sl: se.sl + step.se.sl, st: se.st + step.se.st }; }
    }
    if (step.colorGroup) {
      colorGroup = { ...step.colorGroup }; // always absolute replace
    }
  }
  return { st, sp, w, rotate, scale, offset, d, me, se, colorGroup };
}

// ============================================================================
// BAKE – collapse full spec into minimal vectors
// ============================================================================

/**
 * Convert a full specification (with history, me, se, etc.) into a baked version
 * containing only the final vectors: d, lc, tr, gs (and identifiers/content).
 */
export function bake(spec: UniCompSpec): UniCompSpec {
  const bakedSymbols: SymbolSpec[] = spec.symbols.map(sym => {
    // Start with base symbol (char, start, end, references)
    const baked: SymbolSpec = {
      char: sym.char,
      start: sym.start,
      end: sym.end,
    };
    if (sym.refId) baked.refId = sym.refId;
    if (sym.refName) baked.refName = sym.refName;
    if (sym.refClass) baked.refClass = sym.refClass;
    if (sym.id) baked.id = sym.id;
    if (sym.className) baked.className = sym.className;
    if (sym.name) baked.name = sym.name;
    if (sym.fontFamily) baked.fontFamily = sym.fontFamily;

    // Resolve history if present
    let resolved: ReturnType<typeof resolveHistory> = {};
    if (sym.history && sym.history.length > 0) {
      resolved = resolveHistory(sym.history);
    } else {
      // If no history, use current individual params as resolved
      resolved = {
        st: sym.st,
        sp: sym.sp,
        rotate: sym.rotate,
        scale: sym.scale,
        offset: sym.offset,
        d: sym.bounds ? { x: sym.bounds.w, y: sym.bounds.h } : undefined,
      };
    }

    // Compute final d = [o + me + s + se]
    // o = offset (resolved.offset)
    // me = resolved.me
    // s = scale (resolved.scale) – but scale is multiplicative factor, not additive in cells.
    // Actually, according to your spec: d = [o + me] + [s + se] where s is size in cells.
    // We need to get base size from somewhere. For now, assume base size = (1,1) cell.
    // In real implementation, we need to know original size before scaling.
    // Here we approximate: if scale exists, it multiplies the base size (1 cell) and adds se expansion.
    let startX = 0, startY = 0, endX = 0, endY = 0;
    if (resolved.offset) {
      startX = resolved.offset.x;
      startY = resolved.offset.y;
    }
    if (resolved.me) {
      startX += resolved.me.el;
      startY += resolved.me.et;
    }
    // Base size: we assume each symbol originally occupies 1 cell (width=1, height=1)
    let width = 1, height = 1;
    if (resolved.scale) {
      width = resolved.scale.x;
      height = resolved.scale.y;
    }
    if (resolved.se) {
      width += resolved.se.sl;
      height += resolved.se.st;
    }
    endX = startX + width - 1;
    endY = startY + height - 1;
    baked.bounds = { w: width, h: height };
    // Store final d as start/end indices
    const gridWidth = spec.gridWidth;
    const startIdx = startY * gridWidth + startX;
    const endIdx = endY * gridWidth + endX;
    baked.start = startIdx;
    baked.end = endIdx;

    // Build lc vector
    const lc: LCVector = {};
    if (sym.color || (resolved.colorGroup && resolved.colorGroup.c)) {
      lc.c = sym.color || resolved.colorGroup?.c;
    }
    // b compound: if we have strokeWidth and strokeColor, construct compound string
    if (sym.strokeWidth !== undefined && sym.strokeColor) {
      const hslMatch = sym.strokeColor.match(/hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)/);
      if (hslMatch) {
        lc.b = `${sym.strokeWidth}, ${hslMatch[1]}, ${hslMatch[2]}%, ${hslMatch[3]}%` +
               (sym.strokeOpacity !== undefined ? `, ${sym.strokeOpacity}` : '');
      } else {
        lc.b = `${sym.strokeWidth}, ${sym.strokeColor}`;
      }
    } else if (resolved.colorGroup && resolved.colorGroup.b) {
      lc.b = resolved.colorGroup.b;
    }
    // bc compound
    if (sym.background) {
      const hslMatch = sym.background.match(/hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)/);
      if (hslMatch) {
        lc.bc = `${hslMatch[1]}, ${hslMatch[2]}%, ${hslMatch[3]}%` +
                (sym.backgroundOpacity !== undefined ? `, ${sym.backgroundOpacity}` : '') +
                (sym.borderRadius ? `, ${sym.borderRadius}` : '');
      } else {
        lc.bc = sym.background;
      }
    } else if (resolved.colorGroup && resolved.colorGroup.bc) {
      lc.bc = resolved.colorGroup.bc;
    }
    // bb compound
    if (sym.layerBorderWidth !== undefined && sym.layerBorderColor) {
      const hslMatch = sym.layerBorderColor.match(/hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)/);
      if (hslMatch) {
        lc.bb = `${sym.layerBorderWidth}, ${hslMatch[1]}, ${hslMatch[2]}%, ${hslMatch[3]}%` +
                (sym.layerBorderOpacity !== undefined ? `, ${sym.layerBorderOpacity}` : '');
      } else {
        lc.bb = `${sym.layerBorderWidth}, ${sym.layerBorderColor}`;
      }
    } else if (resolved.colorGroup && resolved.colorGroup.bb) {
      lc.bb = resolved.colorGroup.bb;
    }
    if (Object.keys(lc).length > 0) baked.lc = lc;

    // Build tr vector
    const tr: TRVector = {};
    if (sym.flip) tr.f = sym.flip;
    if (resolved.rotate !== undefined) tr.r = resolved.rotate;
    if (sym.margin) tr.m = `${sym.margin.top}t ${sym.margin.right}r ${sym.margin.bottom}b ${sym.margin.left}l`;
    if (resolved.st) tr.st = resolved.st;
    if (resolved.sp) tr.sp = resolved.sp;
    if (resolved.w) tr.w = resolved.w; // note: warp not yet parsed separately
    if (Object.keys(tr).length > 0) baked.tr = tr;

    return baked;
  });

  // Build baked spec
  const bakedSpec: UniCompSpec = {
    gridSize: spec.gridSize,
    gridWidth: spec.gridWidth,
    gridHeight: spec.gridHeight,
    symbols: bakedSymbols,
    raw: spec.raw,
    id: spec.id,
    className: spec.className,
    name: spec.name,
  };

  // Build gs vector for grid
  const gs: GSVector = {};
  if (spec.background) {
    const hslMatch = spec.background.match(/hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)/);
    if (hslMatch) {
      gs.gc = `${hslMatch[1]}, ${hslMatch[2]}%, ${hslMatch[3]}%` +
              (spec.backgroundOpacity !== undefined ? `, ${spec.backgroundOpacity}` : '') +
              (spec.borderRadius ? `, ${spec.borderRadius}` : '');
    } else {
      gs.gc = spec.background;
    }
  }
  if (spec.strokeWidth !== undefined && spec.strokeColor) {
    const hslMatch = spec.strokeColor.match(/hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)/);
    if (hslMatch) {
      gs.gb = `${spec.strokeWidth}, ${hslMatch[1]}, ${hslMatch[2]}%, ${hslMatch[3]}%` +
              (spec.strokeOpacity !== undefined ? `, ${spec.strokeOpacity}` : '');
    } else {
      gs.gb = `${spec.strokeWidth}, ${spec.strokeColor}`;
    }
  }
  if (Object.keys(gs).length > 0) bakedSpec.gs = gs;

  return bakedSpec;
}

// ============================================================================
// STRINGIFY – convert spec back to UniComp text format
// ============================================================================

function serializeParam(key: string, value: string | number, alwaysQuote = false): string {
  const strValue = value.toString();
  if (alwaysQuote || strValue.includes(' ') || strValue.includes(',') || strValue.includes(';') || strValue.includes('=')) {
    return `${key}="${strValue}"`;
  }
  return `${key}=${strValue}`;
}

function serializeCompound(key: string, value: string): string {
  return `${key}="${value}"`;
}

// ============================================================================
// HISTORY STEP SERIALIZATION
// ============================================================================

function _serNum(n: number): string {
  if (Number.isInteger(n)) return n.toString();
  return parseFloat(n.toFixed(5)).toString();
}

function _serPair(op: DeltaOp, x: number, y: number, key: string): string {
  const sx = _serNum(x);
  const sy = _serNum(y);
  if (op === '=') return `${key}=${sx},${sy}`;
  return `${key}${op}${sx},${sy}`;
}

function _serNum1(op: DeltaOp, v: number, key: string): string {
  const sv = _serNum(v);
  if (op === '=') return `${key}=${sv}`;
  return `${key}${op}${sv}`;
}

function serializeStepBlock(step: HistoryStep, isKeyframe: boolean): string {
  const parts: string[] = [];

  if (isKeyframe) {
    parts.push(`k=${step.index}`);
    if ((step as KeyframeStep).duration > 0) {
      parts.push(`t=${_serNum((step as KeyframeStep).duration)}`);
    }
  } else {
    parts.push(`h=${step.index}`);
  }

  if (step.rotate)  parts.push(_serNum1(step.rotate.op, step.rotate.value, 'r'));
  if (step.scale)   parts.push(_serPair(step.scale.op, step.scale.x, step.scale.y, 's'));
  if (step.offset)  parts.push(_serPair(step.offset.op, step.offset.x, step.offset.y, 'o'));
  if (step.st)      parts.push(_serPair(step.st.op, step.st.angle, step.st.force, 'st'));
  if (step.sp)      parts.push(_serPair(step.sp.op, step.sp.angle, step.sp.force, 'sp'));
  if (step.w)       parts.push(_serPair(step.w.op, step.w.angle, step.w.force, 'w'));
  if (step.d)       parts.push(_serPair(step.d.op, step.d.x, step.d.y, 'd'));
  if (step.me) {
    if (step.me.el !== 0) parts.push(`el=${_serNum(step.me.el)}`);
    if (step.me.et !== 0) parts.push(`et=${_serNum(step.me.et)}`);
  }
  if (step.se) {
    parts.push(`se=${_serNum(step.se.sl)},${_serNum(step.se.st)}`);
  }
  if (step.colorGroup) {
    const cg = step.colorGroup;
    if (cg.c)                       parts.push(`c="${cg.c}"`);
    if (cg.b)                       parts.push(`b="${cg.b}"`);
    if (cg.bc)                      parts.push(`bc="${cg.bc}"`);
    if (cg.bb)                      parts.push(`bb="${cg.bb}"`);
    if (cg.opacity !== undefined)   parts.push(`a=${cg.opacity}`);
  }

  return `[${parts.join(';')}]`;
}

export function stringifySpec(spec: UniCompSpec, baked = false): string {
  const gridPart = spec.gridWidth === spec.gridHeight 
    ? `(${spec.gridWidth})` 
    : `(${spec.gridWidth}×${spec.gridHeight})`;
  
  // Grid-level params
  const gridParams: string[] = [];
  if (spec.id) gridParams.push(serializeParam('id', spec.id));
  if (spec.className) gridParams.push(serializeParam('class', spec.className));
  if (spec.name) gridParams.push(serializeParam('n', spec.name));
  if (spec.gs) {
    if (spec.gs.gc) gridParams.push(serializeCompound('gc', spec.gs.gc));
    if (spec.gs.gb) gridParams.push(serializeCompound('gb', spec.gs.gb));
  } else {
    if (spec.background) {
      const gcMatch = spec.background.match(/hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)/);
      if (gcMatch) {
        let gcVal = `${gcMatch[1]}, ${gcMatch[2]}%, ${gcMatch[3]}%`;
        if (spec.backgroundOpacity !== undefined && spec.backgroundOpacity < 1) gcVal += `, ${spec.backgroundOpacity}`;
        if (spec.borderRadius) gcVal += `, ${spec.borderRadius}`;
        gridParams.push(serializeCompound('gc', gcVal));
      } else {
        gridParams.push(serializeParam('gc', spec.background));
      }
    }
    if (spec.strokeWidth !== undefined && spec.strokeColor) {
      const hslMatch = spec.strokeColor.match(/hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)/);
      if (hslMatch) {
        let gbVal = `${spec.strokeWidth}, ${hslMatch[1]}, ${hslMatch[2]}%, ${hslMatch[3]}%`;
        if (spec.strokeOpacity !== undefined && spec.strokeOpacity < 1) gbVal += `, ${spec.strokeOpacity}`;
        gridParams.push(serializeCompound('gb', gbVal));
      } else {
        gridParams.push(serializeParam('gb', `${spec.strokeWidth}, ${spec.strokeColor}`));
      }
    }
    if (spec.opacity !== undefined && spec.opacity < 1) gridParams.push(`a=${spec.opacity}`);
  }
  const gridParamsPart = gridParams.length > 0 ? `[${gridParams.join(';')}]` : '';

  const symbolsPart = spec.symbols.map(sym => {
    const charPart = (needsQuoting(sym.char) || sym.char.length > 1) ? `"${sym.char}"` : sym.char;
    const params: string[] = [];

    if (baked) {
      // Baked representation: only vectors and identifiers
      if (sym.id) params.push(serializeParam('id', sym.id));
      if (sym.className) params.push(serializeParam('class', sym.className));
      if (sym.name) params.push(serializeParam('n', sym.name));
      if (sym.fontFamily) params.push(serializeParam('font', sym.fontFamily));
      if (sym.lc) {
        if (sym.lc.c) params.push(serializeCompound('c', sym.lc.c));
        if (sym.lc.b) params.push(serializeCompound('b', sym.lc.b));
        if (sym.lc.bc) params.push(serializeCompound('bc', sym.lc.bc));
        if (sym.lc.bb) params.push(serializeCompound('bb', sym.lc.bb));
      }
      if (sym.tr) {
        if (sym.tr.f) params.push(serializeParam('f', sym.tr.f));
        if (sym.tr.r !== undefined) params.push(serializeParam('r', sym.tr.r));
        if (sym.tr.m) params.push(serializeParam('m', sym.tr.m));
        if (sym.tr.st) params.push(`st="${sym.tr.st.angle},${sym.tr.st.force}"`);
        if (sym.tr.sp) params.push(`sp="${sym.tr.sp.angle},${sym.tr.sp.force}"`);
        if (sym.tr.w) params.push(`w="${sym.tr.w.angle},${sym.tr.w.force}"`);
      }
      // d is already baked into start/end, no need to output d param
    } else {
      // Helper: build border/background compound params (shared by history and flat paths)
      const buildCompoundParams = (): string[] => {
        const cParams: string[] = [];
        if (sym.strokeWidth !== undefined && sym.strokeColor) {
          const hslMatch = sym.strokeColor.match(/hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)/);
          if (hslMatch) {
            let bVal = `${sym.strokeWidth}, ${hslMatch[1]}, ${hslMatch[2]}%, ${hslMatch[3]}%`;
            if (sym.strokeOpacity !== undefined && sym.strokeOpacity < 1) bVal += `, ${sym.strokeOpacity}`;
            cParams.push(serializeCompound('b', bVal));
          } else {
            cParams.push(serializeParam('b', `${sym.strokeWidth}, ${sym.strokeColor}`));
          }
        }
        if (sym.background) {
          const hslMatch = sym.background.match(/hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)/);
          if (hslMatch) {
            let bcVal = `${hslMatch[1]}, ${hslMatch[2]}%, ${hslMatch[3]}%`;
            if (sym.backgroundOpacity !== undefined && sym.backgroundOpacity < 1) bcVal += `, ${sym.backgroundOpacity}`;
            if (sym.borderRadius) bcVal += `, ${sym.borderRadius}`;
            cParams.push(serializeCompound('bc', bcVal));
          } else {
            cParams.push(serializeParam('bc', sym.background));
          }
        }
        if (sym.layerBorderWidth !== undefined && sym.layerBorderColor) {
          const hslMatch = sym.layerBorderColor.match(/hsl\(\s*([\d.]+)\s*,\s*([\d.]+)%?\s*,\s*([\d.]+)%?\s*\)/);
          if (hslMatch) {
            let bbVal = `${sym.layerBorderWidth}, ${hslMatch[1]}, ${hslMatch[2]}%, ${hslMatch[3]}%`;
            if (sym.layerBorderOpacity !== undefined && sym.layerBorderOpacity < 1) bbVal += `, ${sym.layerBorderOpacity}`;
            cParams.push(serializeCompound('bb', bbVal));
          } else {
            cParams.push(serializeParam('bb', `${sym.layerBorderWidth}, ${sym.layerBorderColor}`));
          }
        }
        return cParams;
      };

      if (sym.history && sym.history.length > 0) {
        // --- Symbols with history: serialize step blocks ---
        const stepBlocksStr = sym.history.map(s => serializeStepBlock(s, false)).join('');

        // Non-transform flat params (not encoded in history steps)
        const extraParams: string[] = [];
        if (sym.flip)        extraParams.push(serializeParam('f', sym.flip));
        if (sym.fontFamily)  extraParams.push(serializeParam('font', sym.fontFamily));
        if (sym.id)          extraParams.push(serializeParam('id', sym.id));
        if (sym.className)   extraParams.push(serializeParam('class', sym.className));
        if (sym.name)        extraParams.push(serializeParam('n', sym.name));
        if (sym.margin)      extraParams.push(`m="${sym.margin.top}t ${sym.margin.right}r ${sym.margin.bottom}b ${sym.margin.left}l"`);
        if (sym.opacity !== undefined && sym.opacity < 1) extraParams.push(`a=${sym.opacity}`);
        extraParams.push(...buildCompoundParams());

        const extraParamsPart = extraParams.length > 0 ? `[${extraParams.join(';')}]` : '';
        const prefix = sym.refId ? `#${sym.refId}` : sym.refName ? `@${sym.refName}` : sym.refClass ? `.${sym.refClass}` : charPart;
        return `${prefix}${stepBlocksStr}${extraParamsPart}${sym.start}-${sym.end}`;

      } else if (sym.keyframes && sym.keyframes.length > 0) {
        // --- Symbols with keyframes: serialize keyframe blocks ---
        const kfBlocksStr = sym.keyframes.map(s => serializeStepBlock(s, true)).join('');

        const extraParams: string[] = [];
        if (sym.flip)        extraParams.push(serializeParam('f', sym.flip));
        if (sym.fontFamily)  extraParams.push(serializeParam('font', sym.fontFamily));
        if (sym.id)          extraParams.push(serializeParam('id', sym.id));
        if (sym.className)   extraParams.push(serializeParam('class', sym.className));
        if (sym.name)        extraParams.push(serializeParam('n', sym.name));
        if (sym.margin)      extraParams.push(`m="${sym.margin.top}t ${sym.margin.right}r ${sym.margin.bottom}b ${sym.margin.left}l"`);
        if (sym.opacity !== undefined && sym.opacity < 1) extraParams.push(`a=${sym.opacity}`);
        extraParams.push(...buildCompoundParams());

        const extraParamsPart = extraParams.length > 0 ? `[${extraParams.join(';')}]` : '';
        const prefix = sym.refId ? `#${sym.refId}` : sym.refName ? `@${sym.refName}` : sym.refClass ? `.${sym.refClass}` : charPart;
        return `${prefix}${kfBlocksStr}${extraParamsPart}${sym.start}-${sym.end}`;

      } else {
        // --- No history: full editable flat representation ---
        if (sym.color)               params.push(serializeParam('c', sym.color));
        if (sym.rotate !== undefined) params.push(serializeParam('r', sym.rotate));
        if (sym.flip)                params.push(serializeParam('f', sym.flip));
        if (sym.fontFamily)          params.push(serializeParam('font', sym.fontFamily));
        if (sym.id)                  params.push(serializeParam('id', sym.id));
        if (sym.className)           params.push(serializeParam('class', sym.className));
        if (sym.name)                params.push(serializeParam('n', sym.name));
        if (sym.scale) {
          const sx = _serNum(sym.scale.x);
          const sy = _serNum(sym.scale.y);
          params.push(sym.scale.y !== sym.scale.x ? `s=${sx},${sy}` : `s=${sx}`);
        }
        if (sym.sp)     params.push(`sp="${_serNum(sym.sp.angle)},${_serNum(sym.sp.force)}"`);
        if (sym.st)     params.push(`st="${_serNum(sym.st.angle)},${_serNum(sym.st.force)}"`);
        if (sym.w)      params.push(`w="${_serNum(sym.w.angle)},${_serNum(sym.w.force)}"`);
        if (sym.offset) params.push(`o=${_serNum(sym.offset.x)},${_serNum(sym.offset.y)}`);
        if (sym.margin) params.push(`m="${sym.margin.top}t ${sym.margin.right}r ${sym.margin.bottom}b ${sym.margin.left}l"`);
        if (sym.opacity !== undefined && sym.opacity < 1) params.push(`a=${sym.opacity}`);
        params.push(...buildCompoundParams());
      }
    }

    const paramsPart = params.length > 0 ? `[${params.join(';')}]` : '';

    if (sym.refId) return `#${sym.refId}${paramsPart}${sym.start}-${sym.end}`;
    if (sym.refName) return `@${sym.refName}${paramsPart}${sym.start}-${sym.end}`;
    if (sym.refClass) return `.${sym.refClass}${paramsPart}${sym.start}-${sym.end}`;
    return `${charPart}${paramsPart}${sym.start}-${sym.end}`;
  }).join(';');

  return `${gridPart}${gridParamsPart}:${symbolsPart}`;
}

// ============================================================================
// REGISTRY – stores composed blocks by id, name, class
// ============================================================================

export interface RegistryEntry {
  id?: string;
  name?: string;
  className?: string;
  raw: string;
  spec: UniCompSpec;
}

export class UniCompRegistry {
  private byId: Map<string, RegistryEntry> = new Map();
  private byName: Map<string, RegistryEntry> = new Map();
  private byClass: Map<string, RegistryEntry> = new Map();

  clear() {
    this.byId.clear();
    this.byName.clear();
    this.byClass.clear();
  }

  register(entry: RegistryEntry) {
    if (entry.id) this.byId.set(entry.id, entry);
    if (entry.name) this.byName.set(entry.name, entry);
    if (entry.className) this.byClass.set(entry.className, entry);
  }

  getById(id: string): RegistryEntry | undefined {
    return this.byId.get(id);
  }

  getByName(name: string): RegistryEntry | undefined {
    return this.byName.get(name);
  }

  getByClass(className: string): RegistryEntry | undefined {
    return this.byClass.get(className);
  }

  resolve(symbol: SymbolSpec): RegistryEntry | undefined {
    if (symbol.refId) return this.getById(symbol.refId);
    if (symbol.refName) return this.getByName(symbol.refName);
    if (symbol.refClass) return this.getByClass(symbol.refClass);
    return undefined;
  }

  get entries(): RegistryEntry[] {
    return Array.from(this.byId.values());
  }

  get size(): number {
    return this.byId.size + this.byName.size + this.byClass.size;
  }
}

// Global registry instance
let globalRegistry = new UniCompRegistry();

export function getRegistry(): UniCompRegistry {
  return globalRegistry;
}

export function resetRegistry(): UniCompRegistry {
  globalRegistry = new UniCompRegistry();
  return globalRegistry;
}

// ============================================================================
// PUBLIC API
// ============================================================================

export function parseUniComp(input: string): ParseResult {
  try {
    const tokenizer = new Tokenizer(input);
    const tokens = tokenizer.tokenize();
    const parser = new Parser(tokens);
    return parser.parse();
  } catch (e) {
    return {
      success: false,
      error: {
        message: e instanceof Error ? e.message : 'Tokenization error',
      },
    };
  }
}

export function parseMultiLine(input: string): MultiLineParseResult {
  const lines = input.split('\n');
  const blocks: ParsedBlock[] = [];
  const errorLines: ErrorLine[] = [];
  let validCount = 0;
  let errorCount = 0;

  const registry = resetRegistry();

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const trimmed = line.trim();

    if (!trimmed || isCommentLine(trimmed)) {
      return;
    }

    const result = parseUniComp(trimmed);
    
    if (result.success) {
      validCount++;
      blocks.push({
        lineNumber,
        raw: line,
        result,
        name: result.spec.name || result.spec.id || `Line ${lineNumber}`,
      });

      if (result.spec.id || result.spec.name || result.spec.className) {
        registry.register({
          id: result.spec.id,
          name: result.spec.name,
          className: result.spec.className,
          raw: trimmed,
          spec: result.spec,
        });
      }
    } else {
      const failResult = result as { success: false; error: ParseError };
      errorCount++;
      errorLines.push({
        lineNumber,
        column: failResult.error.column,
        message: failResult.error.message,
        raw: line,
      });
      blocks.push({
        lineNumber,
        raw: line,
        result,
      });
    }
  });

  return {
    blocks,
    totalLines: lines.length,
    validCount,
    errorCount,
    errorLines,
  };
}

function isCommentLine(trimmed: string): boolean {
  return (
    trimmed.startsWith('#') ||
    trimmed.startsWith('//') ||
    trimmed.startsWith('--') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('<!--') ||
    trimmed.startsWith("'''") ||
    trimmed.startsWith('"""')
  );
}

// ============================================================================
// COORDINATE UTILITIES
// ============================================================================

export function getRect(start: number, end: number, gridWidth: number) {
  const x1 = start % gridWidth;
  const y1 = Math.floor(start / gridWidth);
  const x2 = end % gridWidth;
  const y2 = Math.floor(end / gridWidth);

  return {
    x1: Math.min(x1, x2),
    y1: Math.min(y1, y2),
    x2: Math.max(x1, x2),
    y2: Math.max(y1, y2),
    width: Math.abs(x2 - x1) + 1,
    height: Math.abs(y2 - y1) + 1,
  };
}

export function linearToCoords(index: number, gridWidth: number) {
  return {
    x: index % gridWidth,
    y: Math.floor(index / gridWidth),
  };
}

export function symbolToCoords(sym: { char: string; start: number; end: number }, gridWidth: number) {
  const x = sym.start % gridWidth;
  const y = Math.floor(sym.start / gridWidth);
  const ex = sym.end % gridWidth;
  const ey = Math.floor(sym.end / gridWidth);
  return { x, y, w: ex - x + 1, h: ey - y + 1 };
}

export function coordsToSymbolIndices(coords: { x: number; y: number; w: number; h: number }, gridWidth: number) {
  const start = coords.y * gridWidth + coords.x;
  const end = (coords.y + coords.h - 1) * gridWidth + (coords.x + coords.w - 1);
  return { start, end };
}

export function resizeGrid(input: string, newWidth: number, newHeight: number): string {
  const result = parseUniComp(input);
  if (!result.success) return input;

  const oldWidth = result.spec.gridWidth;
  const spec = result.spec;

  // Remap each symbol's start/end indices
  for (const sym of spec.symbols) {
    const x1 = sym.start % oldWidth;
    const y1 = Math.floor(sym.start / oldWidth);
    const x2 = sym.end % oldWidth;
    const y2 = Math.floor(sym.end / oldWidth);

    const clampedX1 = Math.min(x1, newWidth - 1);
    const clampedY1 = Math.min(y1, newHeight - 1);
    const clampedX2 = Math.min(x2, newWidth - 1);
    const clampedY2 = Math.min(y2, newHeight - 1);

    sym.start = clampedY1 * newWidth + clampedX1;
    sym.end = clampedY2 * newWidth + clampedX2;
  }

  spec.gridWidth = newWidth;
  spec.gridHeight = newHeight;

  return stringifySpec(spec);
}

// ============================================================================
// HISTORY MANIPULATION UTILITIES
// ============================================================================

export function appendTransformToHistory(
  sym: SymbolSpec,
  paramType: 'st' | 'sp' | 'w' | 'rotate' | 'scale' | 'offset' | 'd' | 'colorGroup',
  newValue: { angle: number; force: number } | number | { x: number; y: number } | DeltaColor,
): void {
  if (!sym.history) sym.history = [];

  const nextIndex = sym.history.length > 0 ? Math.max(...sym.history.map(s => s.index)) + 1 : 0;

  if (paramType === 'colorGroup') {
    const colorVal = newValue as DeltaColor;
    const step: HistoryStep = { index: nextIndex, colorGroup: { ...colorVal, op: '=' } };
    sym.history.push(step);
    if (colorVal.c !== undefined) sym.color = colorVal.c;
    if (colorVal.b) {
      // parse b into parts and set stroke fields
      const parts = colorVal.b.split(',').map(p => p.trim());
      if (parts.length >= 4) {
        sym.strokeWidth = parseFloat(parts[0]);
        sym.strokeColor = `hsl(${parts[1]}, ${parts[2]}, ${parts[3]})`;
        if (parts[4]) sym.strokeOpacity = parseFloat(parts[4]);
      }
    }
    if (colorVal.bc) {
      const parts = colorVal.bc.split(',').map(p => p.trim());
      if (parts.length >= 3) {
        sym.background = `hsl(${parts[1]}, ${parts[2]}, ${parts[3]})`;
        if (parts[4]) sym.backgroundOpacity = parseFloat(parts[4]);
        if (parts[5]) sym.borderRadius = parts[5];
      }
    }
    if (colorVal.bb) {
      const parts = colorVal.bb.split(',').map(p => p.trim());
      if (parts.length >= 4) {
        sym.layerBorderWidth = parseFloat(parts[0]);
        sym.layerBorderColor = `hsl(${parts[1]}, ${parts[2]}, ${parts[3]})`;
        if (parts[4]) sym.layerBorderOpacity = parseFloat(parts[4]);
      }
    }
    if (colorVal.opacity !== undefined) sym.opacity = colorVal.opacity;
    return;
  }

  if (nextIndex === 0) {
    const step: HistoryStep = { index: 0 };
    if (paramType === 'st' && typeof newValue === 'object' && 'angle' in newValue) {
      step.st = { op: '=', angle: (newValue as any).angle, force: (newValue as any).force };
      sym.st = { angle: (newValue as any).angle, force: (newValue as any).force };
    } else if (paramType === 'sp' && typeof newValue === 'object' && 'angle' in newValue) {
      step.sp = { op: '=', angle: (newValue as any).angle, force: (newValue as any).force };
      sym.sp = { angle: (newValue as any).angle, force: (newValue as any).force };
    } else if (paramType === 'w' && typeof newValue === 'object' && 'angle' in newValue) {
      step.w = { op: '=', angle: (newValue as any).angle, force: (newValue as any).force };
      sym.w = { angle: (newValue as any).angle, force: (newValue as any).force };
    } else if (paramType === 'rotate' && typeof newValue === 'number') {
      step.rotate = { op: '=', value: newValue };
      sym.rotate = newValue;
    } else if (paramType === 'scale' && typeof newValue === 'object' && 'x' in newValue) {
      step.scale = { op: '=', x: (newValue as any).x, y: (newValue as any).y };
      sym.scale = { x: (newValue as any).x, y: (newValue as any).y };
    } else if (paramType === 'offset' && typeof newValue === 'object' && 'x' in newValue) {
      step.offset = { op: '=', x: (newValue as any).x, y: (newValue as any).y };
      sym.offset = { x: (newValue as any).x, y: (newValue as any).y };
    } else if (paramType === 'd' && typeof newValue === 'object' && 'x' in newValue) {
      step.d = { op: '=', x: (newValue as any).x, y: (newValue as any).y };
      sym.bounds = { w: (newValue as any).x, h: (newValue as any).y };
    }
    sym.history.push(step);
  } else {
    const accumulated = resolveHistory(sym.history);
    const step: HistoryStep = { index: nextIndex };
    if (paramType === 'st' && typeof newValue === 'object' && 'angle' in newValue) {
      const prev = accumulated.st || { angle: 0, force: 0 };
      step.st = { op: '+=', angle: (newValue as any).angle - prev.angle, force: (newValue as any).force - prev.force };
      sym.st = { angle: (newValue as any).angle, force: (newValue as any).force };
    } else if (paramType === 'sp' && typeof newValue === 'object' && 'angle' in newValue) {
      const prev = accumulated.sp || { angle: 0, force: 0 };
      step.sp = { op: '+=', angle: (newValue as any).angle - prev.angle, force: (newValue as any).force - prev.force };
      sym.sp = { angle: (newValue as any).angle, force: (newValue as any).force };
    } else if (paramType === 'w' && typeof newValue === 'object' && 'angle' in newValue) {
      const prev = accumulated.w || { angle: 0, force: 0 };
      step.w = { op: '+=', angle: (newValue as any).angle - prev.angle, force: (newValue as any).force - prev.force };
      sym.w = { angle: (newValue as any).angle, force: (newValue as any).force };
    } else if (paramType === 'rotate' && typeof newValue === 'number') {
      const prev = accumulated.rotate ?? 0;
      step.rotate = { op: '+=', value: newValue - prev };
      sym.rotate = newValue;
    } else if (paramType === 'scale' && typeof newValue === 'object' && 'x' in newValue) {
      const prev = accumulated.scale || { x: 1, y: 1 };
      step.scale = { op: '+=', x: (newValue as any).x - prev.x, y: (newValue as any).y - prev.y };
      sym.scale = { x: (newValue as any).x, y: (newValue as any).y };
    } else if (paramType === 'offset' && typeof newValue === 'object' && 'x' in newValue) {
      const prev = accumulated.offset || { x: 0, y: 0 };
      step.offset = { op: '+=', x: (newValue as any).x - prev.x, y: (newValue as any).y - prev.y };
      sym.offset = { x: (newValue as any).x, y: (newValue as any).y };
    } else if (paramType === 'd' && typeof newValue === 'object' && 'x' in newValue) {
      const prev = accumulated.d || { x: 0, y: 0 };
      step.d = { op: '+=', x: (newValue as any).x - prev.x, y: (newValue as any).y - prev.y };
      sym.bounds = { w: (newValue as any).x, h: (newValue as any).y };
    }
    sym.history.push(step);
  }
}

export function undoLastHistoryParam(
  sym: SymbolSpec,
  paramType: 'st' | 'sp' | 'w' | 'rotate' | 'scale' | 'offset' | 'd' | 'colorGroup',
): boolean {
  if (!sym.history || sym.history.length === 0) {
    if (paramType === 'st') { if (sym.st) { sym.st = undefined; return true; } }
    if (paramType === 'sp') { if (sym.sp) { sym.sp = undefined; return true; } }
    if (paramType === 'w') { if (sym.w) { sym.w = undefined; return true; } }
    if (paramType === 'rotate') { if (sym.rotate !== undefined) { sym.rotate = undefined; return true; } }
    if (paramType === 'scale') { if (sym.scale) { sym.scale = undefined; return true; } }
    if (paramType === 'offset') { if (sym.offset) { sym.offset = undefined; return true; } }
    if (paramType === 'd') { if (sym.bounds) { sym.bounds = undefined; return true; } }
    if (paramType === 'colorGroup') {
      let changed = false;
      if (sym.color) { sym.color = undefined; changed = true; }
      if (sym.background) { sym.background = undefined; changed = true; }
      if (sym.strokeColor) { sym.strokeColor = undefined; changed = true; }
      if (sym.strokeWidth) { sym.strokeWidth = undefined; changed = true; }
      if (sym.strokeOpacity !== undefined) { sym.strokeOpacity = undefined; changed = true; }
      if (sym.layerBorderWidth) { sym.layerBorderWidth = undefined; changed = true; }
      if (sym.layerBorderColor) { sym.layerBorderColor = undefined; changed = true; }
      if (sym.layerBorderOpacity !== undefined) { sym.layerBorderOpacity = undefined; changed = true; }
      return changed;
    }
    return false;
  }

  for (let i = sym.history.length - 1; i >= 0; i--) {
    const step = sym.history[i];
    const hasParam = (paramType === 'st' && step.st) ||
                     (paramType === 'sp' && step.sp) ||
                     (paramType === 'w' && step.w) ||
                     (paramType === 'rotate' && step.rotate) ||
                     (paramType === 'scale' && step.scale) ||
                     (paramType === 'offset' && step.offset) ||
                     (paramType === 'd' && step.d) ||
                     (paramType === 'colorGroup' && step.colorGroup);
    if (!hasParam) continue;

    if (paramType === 'st') step.st = undefined;
    if (paramType === 'sp') step.sp = undefined;
    if (paramType === 'w') step.w = undefined;
    if (paramType === 'rotate') step.rotate = undefined;
    if (paramType === 'scale') step.scale = undefined;
    if (paramType === 'offset') step.offset = undefined;
    if (paramType === 'd') step.d = undefined;
    if (paramType === 'colorGroup') step.colorGroup = undefined;

    if (!step.st && !step.sp && !step.w && !step.rotate && !step.scale && !step.offset && !step.d && !step.me && !step.se && !step.opacity && !step.colorGroup) {
      sym.history.splice(i, 1);
    }

    sym.history.forEach((s, idx) => s.index = idx);

    if (sym.history.length === 0) {
      sym.history = undefined;
      sym.st = undefined; sym.sp = undefined; sym.rotate = undefined; sym.scale = undefined; sym.offset = undefined; sym.bounds = undefined;
      sym.color = undefined; sym.background = undefined; sym.strokeColor = undefined; sym.strokeWidth = undefined; sym.strokeOpacity = undefined;
      sym.layerBorderWidth = undefined; sym.layerBorderColor = undefined; sym.layerBorderOpacity = undefined;
      sym.backgroundOpacity = undefined; sym.borderRadius = undefined;
    } else {
      const resolved = resolveHistory(sym.history);
      sym.st = resolved.st;
      sym.sp = resolved.sp;
      sym.rotate = resolved.rotate;
      sym.scale = resolved.scale;
      sym.offset = resolved.offset;
      sym.bounds = resolved.d ? { w: resolved.d.x, h: resolved.d.y } : undefined;
      if (resolved.colorGroup) {
        sym.color = resolved.colorGroup.c;
        if (resolved.colorGroup.b) {
          const parts = resolved.colorGroup.b.split(',').map(p => p.trim());
          if (parts.length >= 4) {
            sym.strokeWidth = parseFloat(parts[0]);
            sym.strokeColor = `hsl(${parts[1]}, ${parts[2]}, ${parts[3]})`;
            if (parts[4]) sym.strokeOpacity = parseFloat(parts[4]);
          }
        }
        if (resolved.colorGroup.bc) {
          const parts = resolved.colorGroup.bc.split(',').map(p => p.trim());
          if (parts.length >= 3) {
            sym.background = `hsl(${parts[1]}, ${parts[2]}, ${parts[3]})`;
            if (parts[4]) sym.backgroundOpacity = parseFloat(parts[4]);
            if (parts[5]) sym.borderRadius = parts[5];
          }
        }
        if (resolved.colorGroup.bb) {
          const parts = resolved.colorGroup.bb.split(',').map(p => p.trim());
          if (parts.length >= 4) {
            sym.layerBorderWidth = parseFloat(parts[0]);
            sym.layerBorderColor = `hsl(${parts[1]}, ${parts[2]}, ${parts[3]})`;
            if (parts[4]) sym.layerBorderOpacity = parseFloat(parts[4]);
          }
        }
        if (resolved.colorGroup.opacity !== undefined) sym.opacity = resolved.colorGroup.opacity;
      } else if (paramType === 'colorGroup') {
        sym.color = undefined; sym.background = undefined;
        sym.backgroundOpacity = undefined; sym.borderRadius = undefined;
        sym.strokeColor = undefined; sym.strokeWidth = undefined; sym.strokeOpacity = undefined;
        sym.layerBorderWidth = undefined; sym.layerBorderColor = undefined; sym.layerBorderOpacity = undefined;
      }
    }
    return true;
  }
  return false;
}