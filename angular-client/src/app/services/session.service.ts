import { Injectable, Output, EventEmitter } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class SessionService {
  @Output() hasToken: EventEmitter<boolean> = new EventEmitter();

  constructor() {
    if (localStorage.getItem("token") !== null) {
      this.hasToken.emit(true);
    } else {
      this.hasToken.emit(false);
    }
  }

  // Getters
  getToken(): string {
    return localStorage.getItem("token")!;
  }

  getEmail(): string {
    return localStorage.getItem("email")!;
  }

  getId(): string {
    return localStorage.getItem("id")!;
  }

  // Setters
  setToken(value: string): void {
    this.hasToken.emit(true);
    localStorage.setItem("token", value);
  }

  setEmail(value: string): void {
    localStorage.setItem("email", value);
  }

  setId(value: string): void {
    localStorage.setItem("id", value);
  }

  // Clearing saved token in localstorage
  clear(): void {
    localStorage.clear();
    this.hasToken.emit(false);
  }
}
